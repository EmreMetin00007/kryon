"""Thin scope-locked HTTP transport with WireBudget, multi-actor auth/CSRF, and GET dedup."""
from __future__ import annotations

import base64
import binascii
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import html
import json
import math
from pathlib import Path
import random
import re
import socket
import sys
import threading
import time
from typing import Any, Callable, Sequence
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlencode, urljoin, urlsplit, urlunsplit
import uuid
import zlib

import requests
from urllib3 import exceptions as urllib3_exceptions

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_receipts import ReceiptStore  # noqa: E402
from kryon_core.protocol.grpc_web import decode_grpc_web_frames, is_grpc_web_content_type  # noqa: E402
from kryon_core.protocol.websocket_probe import probe_websocket  # noqa: E402
from kryon_core.surface.openapi import extract_openapi_header_auth_names  # noqa: E402
from target_bootstrap import ScopeGuard, match_logout_route  # noqa: E402
from wire_budget import WireBudget  # noqa: E402

DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
STATIC_EXTENSIONS = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_AUTH_OVERRIDE_HEADERS = frozenset({"authorization", "cookie"})
_CSRF_HEADER_NAMES = frozenset({"x-csrf-token", "x-csrftoken", "x-xsrf-token"})
_CUSTOM_TOKEN_RESPONSE_HEADERS: tuple[str, ...] = (
    "x-access-token",
    "x-auth-token",
    "x-token",
    "x-session-token",
    "x-api-token",
)
_ANON_OBSERVED_AUTH_HEADERS = frozenset(_CUSTOM_TOKEN_RESPONSE_HEADERS)
_EXTRA_SENSITIVE_HEADER_NAMES = frozenset({
    "x-csrftoken",
    "x-access-token",
    "x-token",
    "x-session-token",
    "x-api-token",
})
_NON_DISCOVERABLE_AUTH_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "content-type",
    "content-length",
    "user-agent",
    "accept",
    "host",
    "origin",
    "referer",
    "x-csrf-token-next",
}) | _CSRF_HEADER_NAMES
_HTTP_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$")
_RESERVED_GLOBAL_HEADER_NAMES = frozenset({
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})


def normalize_global_headers(raw_headers: dict[str, Any] | None) -> dict[str, str]:
    """Validate operator-supplied headers applied to every actor and browser request."""
    clean: dict[str, str] = {}
    for raw_name, raw_value in (raw_headers or {}).items():
        name = _validate_auth_header_name(raw_name, strict=True)
        if not name:
            raise ValueError("global header name must not be empty")
        if name.lower() in _RESERVED_GLOBAL_HEADER_NAMES:
            raise ValueError(f"global header {name!r} must be supplied through the actor session")
        value = "" if raw_value is None else str(raw_value).strip()
        if not value:
            raise ValueError(f"global header {name!r} value must not be empty")
        if any(ch in value for ch in ("\r", "\n", "\x00")):
            raise ValueError(f"global header {name!r} value contains control characters")
        if len(value) > 8192:
            raise ValueError(f"global header {name!r} value is too long")
        for existing in [k for k in clean if k.lower() == name.lower()]:
            clean.pop(existing, None)
        clean[name] = value
    return clean


def parse_custom_headers(raw_values: Sequence[str] | dict[str, Any] | None) -> dict[str, str]:
    """Parse repeatable ``Name: Value`` strings or a mapping into validated global headers."""
    if raw_values is None:
        return {}
    if isinstance(raw_values, dict):
        return normalize_global_headers(raw_values)
    if isinstance(raw_values, (str, bytes, bytearray)):
        raise ValueError("custom_headers must be a mapping or sequence of 'Name: Value' strings")
    parsed: dict[str, str] = {}
    for raw in raw_values:
        if not isinstance(raw, str):
            raise ValueError(f"custom header entry must be a string, got {type(raw).__name__}")
        text = raw.strip()
        if not text:
            continue
        name, sep, value = text.partition(":")
        clean_name = name.strip()
        clean_value = value.strip()
        if not sep or not clean_name or not clean_value:
            raise ValueError(f"custom header must use 'Name: Value' format: {text!r}")
        for existing in [k for k in parsed if k.lower() == clean_name.lower()]:
            parsed.pop(existing, None)
        parsed[clean_name] = clean_value
    return normalize_global_headers(parsed)


def _merge_headers_ci(base: dict[str, str], overlay: dict[str, str]) -> dict[str, str]:
    """Return a new header dict with ``overlay`` replacing matching keys case-insensitively."""
    merged = dict(base)
    for hk, hv in overlay.items():
        low = hk.lower()
        for existing in [k for k in merged if k.lower() == low and k != hk]:
            merged.pop(existing, None)
        merged[hk] = hv
    return merged
_SESSION_ENVELOPE_SUBKEYS: tuple[str, ...] = (
    "data",
    "result",
    "payload",
    "session",
    "auth",
    "user",
    "response",
    "body",
)
_SESSION_NESTED_PARENTS: tuple[str, ...] = ("data", "result")
_CSRF_RESPONSE_HEADERS: tuple[tuple[str, str], ...] = (
    ("x-csrf-token-next", "X-CSRF-Token"),
    ("x-csrf-token", "X-CSRF-Token"),
    ("x-csrftoken", "X-CSRFToken"),
    ("x-xsrf-token", "X-XSRF-TOKEN"),
)
_CSRF_META_SPECS: dict[str, tuple[str, str]] = {
    "csrf-token": ("X-CSRF-Token", ""),
    "xsrf-token": ("X-XSRF-TOKEN", ""),
    "csrfmiddlewaretoken": ("X-CSRFToken", "csrfmiddlewaretoken"),
    "_token": ("X-CSRF-Token", "_token"),
    "authenticity_token": ("X-CSRF-Token", "authenticity_token"),
}
_CSRF_INPUT_SPECS: dict[str, tuple[str, str]] = {
    "csrfmiddlewaretoken": ("csrfmiddlewaretoken", "X-CSRFToken"),
    "_token": ("_token", "X-CSRF-Token"),
    "authenticity_token": ("authenticity_token", "X-CSRF-Token"),
    "__token__": ("__token__", "X-CSRF-Token"),
    "__requestverificationtoken": ("__RequestVerificationToken", "X-CSRF-Token"),
    "csrf_token": ("csrf_token", "X-CSRF-Token"),
    "_csrf": ("_csrf", "X-CSRF-Token"),
    "csrf": ("csrf", "X-CSRF-Token"),
    "xsrf_token": ("xsrf_token", "X-XSRF-TOKEN"),
}
_CSRF_COOKIE_SPECS: tuple[tuple[str, str, bool], ...] = (
    ("csrftoken", "X-CSRFToken", False),
    ("xsrf-token", "X-XSRF-TOKEN", True),
    ("csrf_token", "X-CSRF-Token", False),
    ("xsrf_token", "X-XSRF-TOKEN", True),
    ("_csrf", "X-CSRF-Token", False),
    ("_csrf_token", "X-CSRF-Token", False),
)
_HTML_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_HTML_INPUT_TAG_RE = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_HTML_ATTR_RE = re.compile(
    r"""([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
_HTML_SKIP_INPUT_TYPES = frozenset({"submit", "button", "reset", "image", "file", "checkbox", "radio"})
_HTML_CSRF_SCAN_LIMIT = 262_144
_DEGRADATION_STATUS_CODES = frozenset({429, 502, 503, 504})
_DEFAULT_MAX_RETRY_AFTER_S = 5.0
_MAX_RATE_LIMIT_RETRIES = 2
_RATE_LIMIT_FALLBACK_BASE_S = 0.5
_ADAPTIVE_DELAY_MIN_S = 0.25
_ADAPTIVE_DELAY_MAX_S = 1.0
_ADAPTIVE_DECAY_FACTOR = 0.5
_ADAPTIVE_DECAY_FLOOR_S = 0.05
_ADAPTIVE_HEALTHY_STREAK_FOR_DECAY = 2
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS = 5
_SSE_DEFAULT_MAX_BYTES = 16384
_SSE_DEFAULT_MAX_DURATION_S = 1.5
_MULTIPART_MAX_FILES = 8
_MULTIPART_MAX_FILE_BYTES = 256 * 1024
_MULTIPART_MAX_TOTAL_BYTES = 512 * 1024
_LOGIN_MISSING_ROUTE_STATUS_CODES = frozenset({404, 405})
_LOGIN_FALLBACK_MAX_CANDIDATES = 3
_LOGIN_FALLBACK_SKIP_EXTENSIONS = STATIC_EXTENSIONS | frozenset({
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
})
_LOGIN_FALLBACK_EXCLUDE_RE = re.compile(
    r"(?:^|[/_.-])(?:"
    r"logout|log[-_]?out|signout|sign[-_]?out|"
    r"register|registration|signup|sign[-_]?up|"
    r"reset|forgot|recover|recovery|revoke|delete|destroy|refresh|"
    r"verify|confirm|activate|unsubscribe"
    r")(?:$|[/_.-])",
    re.IGNORECASE,
)
_LOGIN_FALLBACK_STRONG_RE = re.compile(
    r"(?:^|[/_.-])(?:login|log[-_]?in|signin|sign[-_]?in)(?:$|[/_.-])"
    r"|(?:^|/)auth/token(?:/|$)",
    re.IGNORECASE,
)
_LOGIN_FALLBACK_WEAK_RE = re.compile(
    r"(?:^|[/_.-])sessions?(?:$|[/_.-])",
    re.IGNORECASE,
)


class ScopeViolationError(ValueError):
    """Raised when a requested URL leaves the authorized target origin or hits an excluded path."""


class MethodNotAllowedError(ValueError):
    """Raised when an HTTP method is outside operator-allowed methods."""


class BudgetExhaustedError(RuntimeError):
    """Raised when WireBudget refuses another live HTTP request."""


class ServiceDegradationError(RuntimeError):
    """Raised when consecutive 429/502/503/504 or connection-error (status=0) responses indicate target degradation."""


def normalize_origin(raw_url: str) -> str:
    """Validate and normalize an explicit http(s) origin URL."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ValueError("target URL is required")
    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"invalid origin URL: {raw_url!r}")
    if parsed.username or parsed.password:
        raise ValueError("target URL must not embed credentials")
    return f"{parsed.scheme}://{parsed.netloc}/"


def is_static_asset_url(url: str) -> bool:
    """Return True for static media/font/style assets skipped during discovery."""
    path = urlsplit(str(url or "")).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def _canonical_url(url: str) -> str:
    parsed = urlsplit(url)
    query_items = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    norm_query = urlencode(query_items, doseq=True)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, norm_query, ""))


def _extract_token_from_auth(auth_header: str) -> str:
    parts = str(auth_header or "").strip().split(None, 1)
    return parts[1].strip() if len(parts) == 2 else ""


def _validate_auth_header_name(raw: Any, *, strict: bool = False) -> str:
    """Validate and normalize an HTTP auth header name, rejecting CRLF, NUL, and non-token characters."""
    if raw is None:
        return ""
    if not isinstance(raw, str):
        if strict:
            raise ValueError("auth_header must be a string")
        return ""
    if "\r" in raw or "\n" in raw or "\x00" in raw:
        if strict:
            raise ValueError("auth_header must not contain control characters")
        return ""
    clean = raw.strip()
    if not clean:
        return ""
    if not _HTTP_HEADER_NAME_RE.fullmatch(clean):
        if strict:
            raise ValueError(f"invalid auth_header name: {raw!r}")
        return ""
    return clean


def _redact_extra_sensitive_headers(
    headers: dict[str, str],
    extra_names: AbstractSet[str] = frozenset(),
) -> dict[str, str]:
    """Ensure framework CSRF and custom API token headers are redacted before receipt persistence."""
    if not headers:
        return {}
    sensitive = _EXTRA_SENSITIVE_HEADER_NAMES | extra_names
    out: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k)
        val_str = str(v)
        if key_str.strip().lower() in sensitive and val_str and not val_str.startswith("<REDACTED"):
            digest8 = hashlib.sha256(val_str.encode("utf-8", errors="replace")).hexdigest()[:8]
            out[key_str] = f"<REDACTED:len={len(val_str)},sha256_8={digest8}>"
        else:
            out[key_str] = val_str
    return out


def _redact_framework_csrf_headers(headers: dict[str, str]) -> dict[str, str]:
    """Ensure framework-specific CSRF headers (e.g. X-CSRFToken) are redacted before receipt persistence."""
    return _redact_extra_sensitive_headers(headers)


def _parse_retry_after_seconds(
    headers: dict[str, str] | None,
    *,
    max_retry_after_s: float = _DEFAULT_MAX_RETRY_AFTER_S,
    now: float | None = None,
) -> float | None:
    """Parse HTTP Retry-After (delta-seconds or RFC 7231 HTTP-date), clamped to [0, max_retry_after_s]."""
    if not headers:
        return None
    raw_val = ""
    for k, v in headers.items():
        if str(k).strip().lower() == "retry-after":
            raw_val = str(v or "").strip()
            break
    if not raw_val:
        return None
    cap = max(0.0, float(max_retry_after_s))
    try:
        numeric = float(raw_val)
    except ValueError:
        numeric = math.nan
    if math.isfinite(numeric):
        return max(0.0, min(numeric, cap))
    try:
        dt = parsedate_to_datetime(raw_val)
    except (TypeError, ValueError, OverflowError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now_ts = time.time() if now is None else float(now)
    delta = dt.timestamp() - now_ts
    if not math.isfinite(delta):
        return None
    return max(0.0, min(delta, cap))


def _parse_html_tag_attrs(tag_html: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for match in _HTML_ATTR_RE.finditer(tag_html):
        key = match.group(1).strip().lower()
        raw_val = match.group(2) if match.group(2) is not None else (
            match.group(3) if match.group(3) is not None else (match.group(4) or "")
        )
        attrs[key] = html.unescape(raw_val).strip()
    return attrs


@dataclass
class ActorSession:
    """In-memory credentials and active session state for one actor."""

    alias: str
    role: str = "member"
    tenant: str = ""
    login_payload: dict[str, str] = field(default_factory=dict)
    login_graphql_query: str = ""
    password: str = ""
    base_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    access_token: str = ""
    auth_header_name: str = ""
    auth_header_prefix: str = ""
    refresh_token: str = ""
    refresh_path: str = ""
    csrf_token: str = ""
    csrf_header_name: str = ""
    csrf_field_name: str = ""
    authenticated: bool = False
    dynamic: bool = False
    source_receipt_id: str = ""
    last_auth_status: int | None = None
    last_auth_path: str = ""
    last_auth_error: str = ""
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False, compare=False)

    def collect_secrets(self) -> list[str]:
        with self._lock:
            secrets: list[str] = []
            for candidate in (self.password, self.access_token, self.refresh_token, self.csrf_token):
                if candidate and len(candidate) >= 4:
                    secrets.append(candidate)
            if self.access_token and self.auth_header_prefix:
                prefixed = f"{self.auth_header_prefix}{self.access_token}"
                if len(prefixed) >= 4 and prefixed not in secrets:
                    secrets.append(prefixed)
            if self.csrf_token and len(self.csrf_token) >= 4:
                for encoded in (quote_plus(self.csrf_token), quote(self.csrf_token, safe="")):
                    if encoded and encoded != self.csrf_token and encoded not in secrets:
                        secrets.append(encoded)
            secret_header_names = (
                {"authorization", "cookie", "x-api-key"}
                | _ANON_OBSERVED_AUTH_HEADERS
                | _CSRF_HEADER_NAMES
            )
            clean_auth_hdr = self.auth_header_name.strip().lower()
            if clean_auth_hdr:
                secret_header_names.add(clean_auth_hdr)
            for k, v in self.base_headers.items():
                if k.lower() in secret_header_names and v:
                    secrets.append(v)
                    tok = _extract_token_from_auth(v)
                    if tok:
                        secrets.append(tok)
            for val in self.cookies.values():
                if val and len(val) >= 4:
                    secrets.append(val)
            for val in self.local_storage.values():
                if val and len(val) >= 4:
                    secrets.append(val)
            return secrets

    def build_headers(self, method: str, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        with self._lock:
            extra_items = list((extra_headers or {}).items())
            extra_low = {str(k).strip().lower(): ("" if v is None else str(v)) for k, v in extra_items}
            eff_auth_header = self.auth_header_name.strip()
            use_custom_header = bool(eff_auth_header) and eff_auth_header.lower() != "authorization"
            custom_header_low = eff_auth_header.lower() if use_custom_header else ""
            explicit_authorization = bool(extra_low.get("authorization", "").strip())
            explicit_custom = bool(use_custom_header and extra_low.get(custom_header_low, "").strip())
            override_auth = explicit_authorization or explicit_custom
            override_cookie = bool(extra_low.get("cookie", "").strip())

            headers = dict(self.base_headers)
            # When an explicit Authorization/custom-auth override is supplied without Cookie (or vice
            # versa), suppress the actor's default peer auth channel so a stale session
            # cookie or token does not shadow the tested credential on dual-auth apps.
            if override_auth and "cookie" not in extra_low:
                for ek in [k for k in headers if k.lower() == "cookie"]:
                    headers.pop(ek, None)
            if override_cookie:
                if "authorization" not in extra_low:
                    for ek in [k for k in headers if k.lower() == "authorization"]:
                        headers.pop(ek, None)
                if use_custom_header and custom_header_low not in extra_low:
                    for ek in [k for k in headers if k.lower() == custom_header_low]:
                        headers.pop(ek, None)
            if explicit_authorization and use_custom_header and custom_header_low not in extra_low:
                for ek in [k for k in headers if k.lower() == custom_header_low]:
                    headers.pop(ek, None)

            if self.access_token:
                if use_custom_header:
                    suppress_custom = (
                        (override_cookie and custom_header_low not in extra_low)
                        or (explicit_authorization and custom_header_low not in extra_low)
                    )
                    if not suppress_custom and not any(k.lower() == custom_header_low for k in headers):
                        headers[eff_auth_header] = f"{self.auth_header_prefix}{self.access_token}"
                else:
                    if not (override_cookie and "authorization" not in extra_low):
                        if not any(k.lower() == "authorization" for k in headers):
                            headers["Authorization"] = f"Bearer {self.access_token}"
            if self.cookies and not (override_auth and "cookie" not in extra_low):
                if not any(k.lower() == "cookie" for k in headers):
                    headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(self.cookies.items()))
            if method.upper() in _MUTATING_METHODS and self.csrf_token:
                has_caller_csrf = any(k in _CSRF_HEADER_NAMES for k in extra_low)
                has_existing_csrf = any(k.lower() in _CSRF_HEADER_NAMES for k in headers)
                if not has_caller_csrf and not has_existing_csrf:
                    headers[self.csrf_header_name or "X-CSRF-Token"] = self.csrf_token
            if extra_items:
                for k, v in extra_items:
                    key_str = str(k)
                    key_low = key_str.strip().lower()
                    for existing_key in [ek for ek in headers if ek.lower() == key_low and ek != key_str]:
                        headers.pop(existing_key, None)
                    val_str = "" if v is None else str(v)
                    if val_str == "":
                        headers.pop(key_str, None)
                    else:
                        headers[key_str] = val_str
            return headers


def _extract_session_material_full(
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    body_text: str,
) -> tuple[dict[str, str], str, str, str, str, str, str, str]:
    """Extract (cookies, bearer_token, refresh_token, csrf_token, csrf_header_name, csrf_field_name, auth_header_name, token_source)."""
    captured_cookies = {str(k): str(v) for k, v in (cookies or {}).items() if k and v}
    lower_headers = {str(k).strip().lower(): str(v) for k, v in (headers or {}).items()}
    raw_header_names = {str(k).strip().lower(): str(k).strip() for k in (headers or {}) if str(k).strip()}
    csrf_token = ""
    csrf_header_name = ""
    csrf_field_name = ""
    csrf_from_response_header = False
    for hdr_key, canonical_hdr in _CSRF_RESPONSE_HEADERS:
        hdr_val = (lower_headers.get(hdr_key) or "").strip()
        if hdr_val and not hdr_val.startswith("<REDACTED"):
            csrf_token = hdr_val
            csrf_header_name = canonical_hdr
            csrf_from_response_header = True
            break
    bearer_token = ""
    auth_header_name = ""
    token_source = ""
    auth_hdr = lower_headers.get("authorization", "").strip()
    if auth_hdr:
        extracted_auth = _extract_token_from_auth(auth_hdr)
        if extracted_auth and not extracted_auth.startswith("<REDACTED"):
            bearer_token = extracted_auth
            token_source = "authorization_header"
    if not bearer_token:
        for hdr_key in _CUSTOM_TOKEN_RESPONSE_HEADERS:
            hdr_val = (lower_headers.get(hdr_key) or "").strip()
            if hdr_val and not hdr_val.startswith("<REDACTED"):
                if hdr_val[:7].lower() == "bearer " and hdr_val[7:].strip():
                    hdr_val = hdr_val[7:].strip()
                bearer_token = hdr_val
                auth_header_name = raw_header_names.get(hdr_key, hdr_key)
                token_source = "response_header"
                break
    refresh_token = ""

    stripped = (body_text or "").lstrip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(body_text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            candidates: list[dict[str, Any]] = [parsed]
            for subkey in _SESSION_ENVELOPE_SUBKEYS:
                sub = parsed.get(subkey)
                if isinstance(sub, dict):
                    candidates.append(sub)
            # Support nested envelopes such as {"data": {"login": {...}}} or {"result": {"data": {...}}}.
            for parent_key in _SESSION_NESTED_PARENTS:
                parent_obj = parsed.get(parent_key)
                if isinstance(parent_obj, dict):
                    nested_count = 0
                    for sub_val in parent_obj.values():
                        if isinstance(sub_val, dict):
                            candidates.append(sub_val)
                            nested_count += 1
                            if nested_count >= 8:
                                break
            for obj in candidates:
                if not bearer_token:
                    for tkey in (
                        "access_token",
                        "accessToken",
                        "token",
                        "jwt",
                        "id_token",
                        "idToken",
                        "auth_token",
                        "authToken",
                        "bearer_token",
                        "bearerToken",
                    ):
                        val = obj.get(tkey)
                        if isinstance(val, str) and val.strip() and not val.strip().startswith("<REDACTED"):
                            bearer_token = val.strip()
                            token_source = "json_body"
                            break
                if not refresh_token:
                    for rkey in ("refresh_token", "refreshToken"):
                        ref_val = obj.get(rkey)
                        if isinstance(ref_val, str) and ref_val.strip() and not ref_val.strip().startswith("<REDACTED"):
                            refresh_token = ref_val.strip()
                            break
                if not csrf_token:
                    for ckey in ("csrf_token", "csrfToken", "csrf", "xsrf_token", "xsrfToken"):
                        cval = obj.get(ckey)
                        if isinstance(cval, str) and cval.strip() and not cval.strip().startswith("<REDACTED"):
                            csrf_token = cval.strip()
                            break
    elif body_text:
        html_slice = body_text[:_HTML_CSRF_SCAN_LIMIT]
        html_low = html_slice.lower()
        if "<meta" in html_low or "<input" in html_low:
            if "<meta" in html_low:
                for tag_match in _HTML_META_TAG_RE.finditer(html_slice):
                    attrs = _parse_html_tag_attrs(tag_match.group(0))
                    meta_name = attrs.get("name", "").lower()
                    meta_content = attrs.get("content", "")
                    spec = _CSRF_META_SPECS.get(meta_name)
                    if spec is not None and meta_content:
                        meta_hdr, meta_field = spec
                        if not csrf_token:
                            csrf_token = meta_content
                        if not csrf_header_name:
                            csrf_header_name = meta_hdr
                        if meta_field and not csrf_field_name:
                            csrf_field_name = meta_field
                        break
            if "<input" in html_low:
                for tag_match in _HTML_INPUT_TAG_RE.finditer(html_slice):
                    attrs = _parse_html_tag_attrs(tag_match.group(0))
                    input_type = attrs.get("type", "").lower()
                    if input_type in _HTML_SKIP_INPUT_TYPES:
                        continue
                    raw_name = attrs.get("name", "")
                    input_val = attrs.get("value", "")
                    spec = _CSRF_INPUT_SPECS.get(raw_name.lower())
                    if spec is not None and input_val:
                        canonical_field, input_hdr = spec
                        if not csrf_token:
                            csrf_token = input_val
                        if not csrf_field_name:
                            csrf_field_name = raw_name or canonical_field
                        if not csrf_from_response_header:
                            if not csrf_header_name or canonical_field == "csrfmiddlewaretoken":
                                csrf_header_name = input_hdr
                        break

    if not csrf_token and captured_cookies:
        lower_cookies = {k.lower(): v for k, v in captured_cookies.items()}
        for ckey, cookie_hdr, should_unquote in _CSRF_COOKIE_SPECS:
            cval = (lower_cookies.get(ckey) or "").strip()
            if cval:
                if should_unquote and "%" in cval:
                    cval = unquote(cval).strip()
                if cval:
                    csrf_token = cval
                    if not csrf_header_name:
                        csrf_header_name = cookie_hdr
                    break

    return (
        captured_cookies,
        bearer_token,
        refresh_token,
        csrf_token,
        csrf_header_name,
        csrf_field_name,
        auth_header_name,
        token_source,
    )


def _extract_session_material_details(
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    body_text: str,
) -> tuple[dict[str, str], str, str, str, str, str]:
    """Extract (cookies, bearer_token, refresh_token, csrf_token, csrf_header_name, csrf_field_name)."""
    (
        captured_cookies,
        bearer_token,
        refresh_token,
        csrf_token,
        csrf_header_name,
        csrf_field_name,
        _,
        _,
    ) = _extract_session_material_full(
        headers=headers,
        cookies=cookies,
        body_text=body_text,
    )
    return captured_cookies, bearer_token, refresh_token, csrf_token, csrf_header_name, csrf_field_name


def _extract_session_material_from_response(
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    body_text: str,
) -> tuple[dict[str, str], str, str, str]:
    """Extract (cookies, bearer_token, refresh_token, csrf_token) from an HTTP response."""
    cap_cookies, bearer_token, refresh_token, csrf_token, _, _ = _extract_session_material_details(
        headers=headers,
        cookies=cookies,
        body_text=body_text,
    )
    return cap_cookies, bearer_token, refresh_token, csrf_token


class ActorManager:
    """Manage multi-actor sessions, keeping credentials strictly in harness memory."""

    def __init__(
        self,
        accounts: Sequence[dict[str, Any]] = (),
        *,
        login_path: str = "/api/v1/access/sign-in",
        session_check_path: str = "/api/v1/access/session",
        refresh_path: str = "/api/v1/access/refresh",
        global_headers: dict[str, Any] | None = None,
    ):
        self.login_path = login_path
        self.session_check_path = session_check_path
        self.refresh_path = refresh_path
        self._lock = threading.Lock()
        self._discovered_auth_header: str = ""
        self._discovered_auth_prefix: str = ""
        clean_global_headers = normalize_global_headers(global_headers)
        self._global_headers: dict[str, str] = dict(clean_global_headers)
        self.actors: dict[str, ActorSession] = {
            "anon": ActorSession(
                alias="anon",
                role="anonymous",
                tenant="",
                authenticated=True,
                base_headers=dict(clean_global_headers),
            )
        }
        for raw in accounts:
            if not isinstance(raw, dict) or not raw.get("alias"):
                continue
            alias = str(raw["alias"]).strip()
            if not alias or alias == "anon":
                continue
            account_headers: dict[str, str] = {}
            if isinstance(raw.get("headers"), dict):
                account_headers = _merge_headers_ci(
                    account_headers,
                    {str(k): str(v) for k, v in raw["headers"].items() if k and v is not None},
                )
            if isinstance(raw.get("auth_header"), str) and raw["auth_header"].strip():
                if not any(k.lower() == "authorization" for k in account_headers):
                    account_headers["Authorization"] = raw["auth_header"].strip()
            auth_header_name = _validate_auth_header_name(raw.get("auth_header_name"), strict=False)
            auth_header_prefix = str(raw.get("auth_header_prefix") or "")
            access_token = str(raw.get("session_token") or raw.get("access_token") or "").strip()
            if not access_token:
                auth_val = next(
                    (v for k, v in account_headers.items() if k.lower() == "authorization"),
                    "",
                )
                if auth_val:
                    access_token = _extract_token_from_auth(auth_val)
            cookies: dict[str, str] = {}
            if isinstance(raw.get("cookies"), dict):
                cookies.update({str(k): str(v) for k, v in raw["cookies"].items() if k and v is not None})
            if isinstance(raw.get("cookie"), str) and raw["cookie"].strip():
                if not any(k.lower() == "cookie" for k in account_headers):
                    account_headers["Cookie"] = raw["cookie"].strip()
            base_headers = _merge_headers_ci(clean_global_headers, account_headers)
            local_storage: dict[str, str] = {}
            if isinstance(raw.get("local_storage"), dict):
                for lk, lv in raw["local_storage"].items():
                    if isinstance(lk, str) and isinstance(lv, str) and lk.strip():
                        local_storage[lk.strip()] = lv
            login_graphql_query = str(raw.get("login_graphql_query") or "").strip()
            password = str(raw.get("password") or "")
            login_payload: dict[str, str] = {}
            if password:
                login_payload["password"] = password
                for key in ("work_email", "email", "username"):
                    val = raw.get(key)
                    if isinstance(val, str) and val.strip():
                        login_payload[key] = val.strip()
                        break
            has_preauth = bool(account_headers or access_token or cookies or local_storage)
            self.actors[alias] = ActorSession(
                alias=alias,
                role=str(raw.get("role") or "member").strip() or "member",
                tenant=str(raw.get("tenant") or "").strip(),
                login_payload=login_payload,
                login_graphql_query=login_graphql_query,
                password=password,
                base_headers=base_headers,
                cookies=cookies,
                local_storage=local_storage,
                access_token=access_token,
                auth_header_name=auth_header_name,
                auth_header_prefix=auth_header_prefix,
                refresh_token=str(raw.get("refresh_token") or "").strip(),
                refresh_path=str(raw.get("refresh_path") or "").strip(),
                csrf_token=str(raw.get("csrf_token") or "").strip(),
                csrf_header_name=str(raw.get("csrf_header_name") or "").strip(),
                csrf_field_name=str(raw.get("csrf_field_name") or "").strip(),
                authenticated=has_preauth,
            )

    @property
    def discovered_auth_header(self) -> str:
        with self._lock:
            return self._discovered_auth_header

    def get_discovered_auth_header(self) -> tuple[str, str]:
        with self._lock:
            return self._discovered_auth_header, self._discovered_auth_prefix

    def register_discovered_auth_header(self, header_name: str, prefix: str = "") -> str:
        """Store a preferred non-Authorization API token header discovered from OpenAPI or 2xx traffic."""
        clean = _validate_auth_header_name(header_name, strict=False)
        if not clean or clean.lower() in _NON_DISCOVERABLE_AUTH_HEADERS:
            return ""
        clean_prefix = str(prefix or "")
        with self._lock:
            self._discovered_auth_header = clean
            self._discovered_auth_prefix = clean_prefix
        return clean

    def sensitive_header_names(self) -> frozenset[str]:
        """Return lowercased custom auth header names registered on the manager or any actor."""
        names: set[str] = set()
        with self._lock:
            if self._discovered_auth_header:
                names.add(self._discovered_auth_header.strip().lower())
            sessions = list(self.actors.values())
        for session in sessions:
            with session._lock:
                if session.auth_header_name.strip():
                    names.add(session.auth_header_name.strip().lower())
        return frozenset(names)

    def global_headers(self) -> dict[str, str]:
        """Return a copy of operator headers attached to every actor session."""
        with self._lock:
            return dict(self._global_headers)

    def set_global_headers(self, raw_headers: dict[str, Any] | Sequence[str] | None) -> dict[str, str]:
        """Merge validated operator headers into the manager and all existing actor sessions."""
        incoming = parse_custom_headers(raw_headers)
        if not incoming:
            return self.global_headers()
        with self._lock:
            self._global_headers = _merge_headers_ci(self._global_headers, incoming)
            merged_global = dict(self._global_headers)
            sessions = list(self.actors.values())
        for session in sessions:
            with session._lock:
                # Preserve existing actor-specific headers over newly attached defaults only when
                # they are auth headers; operator custom headers apply to every actor.
                session.base_headers = _merge_headers_ci(session.base_headers, incoming)
        return merged_global

    def get(self, alias: str) -> ActorSession:
        key = str(alias or "anon").strip() or "anon"
        with self._lock:
            if key not in self.actors:
                raise ValueError(f"unknown actor alias: {alias!r}; available: {sorted(self.actors)}")
            return self.actors[key]

    def summaries(self) -> list[dict[str, str]]:
        """Return public non-secret actor metadata safe to show the LLM."""
        with self._lock:
            return [
                {"alias": s.alias, "role": s.role, "tenant": s.tenant}
                for s in self.actors.values()
            ]

    def authenticated_non_anon_aliases(self) -> list[str]:
        """Return sorted non-anon actor aliases that are currently authenticated."""
        with self._lock:
            items = list(self.actors.items())
        out: list[str] = []
        for alias, sess in items:
            if alias == "anon":
                continue
            with sess._lock:
                if sess.authenticated:
                    out.append(alias)
        return sorted(out)

    def unauthenticated_credentialed_aliases(self) -> list[str]:
        """Return sorted non-anon actor aliases with login credentials that are not authenticated."""
        with self._lock:
            items = list(self.actors.items())
        out: list[str] = []
        for alias, sess in items:
            if alias == "anon":
                continue
            with sess._lock:
                if sess.login_payload and not sess.authenticated:
                    out.append(alias)
        return sorted(out)

    def actors_failed_with_missing_login_route(self) -> list[str]:
        """Return sorted credentialed actor aliases whose last login attempt returned 404 or 405."""
        with self._lock:
            items = list(self.actors.items())
        out: list[str] = []
        for alias, sess in items:
            if alias == "anon":
                continue
            with sess._lock:
                if (
                    sess.login_payload
                    and not sess.authenticated
                    and sess.last_auth_status in _LOGIN_MISSING_ROUTE_STATUS_CODES
                ):
                    out.append(alias)
        return sorted(out)

    def all_secrets(self) -> list[str]:
        with self._lock:
            sessions = list(self.actors.values())
        secrets: list[str] = []
        for session in sessions:
            secrets.extend(session.collect_secrets())
        return secrets

    def register_dynamic_session(
        self,
        alias: str,
        *,
        role: str = "member",
        tenant: str = "",
        cookies: dict[str, str] | None = None,
        bearer_token: str | None = None,
        refresh_token: str | None = None,
        csrf_token: str | None = None,
        csrf_header_name: str | None = None,
        csrf_field_name: str | None = None,
        source_receipt_id: str = "",
        base_headers: dict[str, str] | None = None,
        auth_header_name: str | None = None,
        auth_header_prefix: str | None = None,
    ) -> ActorSession:
        """Register or update a dynamic session strictly in harness memory (never exposing secrets)."""
        clean_alias = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(alias or "").strip())[:48]
        if not clean_alias or clean_alias == "anon":
            raise ValueError(f"invalid dynamic session alias: {alias!r}")
        clean_cookies = {str(k): str(v) for k, v in (cookies or {}).items() if k and v}
        clean_bearer = str(bearer_token or "").strip()
        clean_refresh = str(refresh_token or "").strip()
        clean_csrf = str(csrf_token or "").strip()
        clean_csrf_header = str(csrf_header_name or "").strip()
        clean_csrf_field = str(csrf_field_name or "").strip()
        provided_headers = {str(k): str(v) for k, v in (base_headers or {}).items() if k and v}
        clean_headers = _merge_headers_ci(self.global_headers(), provided_headers)
        explicit_auth_header = (
            _validate_auth_header_name(auth_header_name, strict=True)
            if auth_header_name is not None
            else None
        )
        is_auth = bool(clean_cookies or clean_bearer or provided_headers)
        with self._lock:
            if explicit_auth_header is not None:
                eff_auth_header: str | None = explicit_auth_header
                eff_auth_prefix: str | None = "" if auth_header_prefix is None else str(auth_header_prefix)
            elif clean_bearer and self._discovered_auth_header:
                eff_auth_header = self._discovered_auth_header
                eff_auth_prefix = (
                    self._discovered_auth_prefix
                    if auth_header_prefix is None
                    else str(auth_header_prefix)
                )
            else:
                eff_auth_header = None
                eff_auth_prefix = None if auth_header_prefix is None else str(auth_header_prefix)

            existing = self.actors.get(clean_alias)
            if existing is not None:
                with existing._lock:
                    existing.cookies.update(clean_cookies)
                    if eff_auth_header is not None:
                        existing.auth_header_name = eff_auth_header
                    if eff_auth_prefix is not None:
                        existing.auth_header_prefix = eff_auth_prefix
                    if clean_bearer:
                        existing.access_token = clean_bearer
                        target_hdr_low = (
                            existing.auth_header_name.strip().lower()
                            if existing.auth_header_name.strip()
                            else "authorization"
                        )
                        for auth_key in [k for k in existing.base_headers if k.lower() in {"authorization", target_hdr_low}]:
                            existing.base_headers.pop(auth_key, None)
                    if clean_refresh:
                        existing.refresh_token = clean_refresh
                    if clean_csrf:
                        existing.csrf_token = clean_csrf
                    if clean_csrf_header:
                        existing.csrf_header_name = clean_csrf_header
                    if clean_csrf_field:
                        existing.csrf_field_name = clean_csrf_field
                    if clean_headers:
                        existing.base_headers = _merge_headers_ci(existing.base_headers, clean_headers)
                    if role:
                        existing.role = str(role).strip() or existing.role
                    if tenant:
                        existing.tenant = str(tenant).strip()
                    if source_receipt_id:
                        existing.source_receipt_id = str(source_receipt_id)
                    existing.authenticated = bool(existing.authenticated or is_auth)
                    existing.dynamic = True
                return existing
            session = ActorSession(
                alias=clean_alias,
                role=str(role or "member").strip() or "member",
                tenant=str(tenant or "").strip(),
                base_headers=clean_headers,
                cookies=clean_cookies,
                access_token=clean_bearer,
                auth_header_name=eff_auth_header or "",
                auth_header_prefix=eff_auth_prefix or "",
                refresh_token=clean_refresh,
                csrf_token=clean_csrf,
                csrf_header_name=clean_csrf_header,
                csrf_field_name=clean_csrf_field,
                authenticated=is_auth,
                dynamic=True,
                source_receipt_id=str(source_receipt_id or ""),
            )
            self.actors[clean_alias] = session
            return session

    def set_source_receipt_id(self, alias: str, receipt_id: str) -> None:
        with self._lock:
            session = self.actors.get(alias)
        if session is not None:
            with session._lock:
                session.source_receipt_id = str(receipt_id or "")

    def update_from_response(
        self,
        alias: str,
        *,
        headers: dict[str, str],
        cookies: dict[str, str],
        body_text: str,
    ) -> None:
        """Capture rotated CSRF tokens, refreshed tokens, and session cookies."""
        if alias == "anon":
            return
        with self._lock:
            session = self.actors.get(alias)
            disc_hdr = self._discovered_auth_header
            disc_pfx = self._discovered_auth_prefix
        if session is None:
            return
        (
            cap_cookies,
            cap_bearer,
            cap_refresh,
            cap_csrf,
            cap_csrf_header,
            cap_csrf_field,
            cap_auth_header,
            cap_token_source,
        ) = _extract_session_material_full(
            headers=headers,
            cookies=cookies,
            body_text=body_text,
        )
        with session._lock:
            if cap_cookies:
                for cookie_hdr_key in [k for k in session.base_headers if k.lower() == "cookie"]:
                    raw_cookie_hdr = str(session.base_headers.pop(cookie_hdr_key, "") or "")
                    for part in raw_cookie_hdr.split(";"):
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            if ck.strip() and cv.strip():
                                session.cookies.setdefault(ck.strip(), cv.strip())
                for k, v in cap_cookies.items():
                    session.cookies[k] = v
            if cap_csrf:
                session.csrf_token = cap_csrf
            if cap_csrf_header:
                session.csrf_header_name = cap_csrf_header
            if cap_csrf_field:
                session.csrf_field_name = cap_csrf_field
            if cap_bearer:
                if cap_auth_header:
                    session.auth_header_name = cap_auth_header
                    session.auth_header_prefix = ""
                elif cap_token_source == "authorization_header":
                    session.auth_header_name = ""
                    session.auth_header_prefix = ""
                elif (
                    cap_token_source == "json_body"
                    and not session.auth_header_name
                    and not session.access_token
                    and not any(k.lower() == "authorization" for k in session.base_headers)
                    and disc_hdr
                ):
                    session.auth_header_name = disc_hdr
                    session.auth_header_prefix = disc_pfx
                session.access_token = cap_bearer
                target_hdr_low = (
                    session.auth_header_name.strip().lower()
                    if session.auth_header_name.strip()
                    else "authorization"
                )
                for auth_key in [k for k in session.base_headers if k.lower() in {"authorization", target_hdr_low}]:
                    session.base_headers.pop(auth_key, None)
                session.authenticated = True
            if cap_refresh:
                session.refresh_token = cap_refresh

    def get_browser_auth_state(self, actor_alias: str) -> dict[str, Any]:
        """Return host-side cookies, auth headers, and local_storage for browser contexts (never expose to LLM)."""
        session = self.get(actor_alias)
        if session.alias == "anon":
            return {"cookies": {}, "headers": {}}
        with session._lock:
            if not session.authenticated:
                return {"cookies": {}, "headers": {}}
            cookies: dict[str, str] = dict(session.cookies)
            auth_headers: dict[str, str] = {}
            for key, val in session.base_headers.items():
                if key.lower() == "cookie":
                    for part in str(val).split(";"):
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            ck_clean = ck.strip()
                            cv_clean = cv.strip()
                            if ck_clean and cv_clean:
                                cookies.setdefault(ck_clean, cv_clean)
                else:
                    auth_headers[str(key)] = str(val)
            if session.access_token:
                eff_auth_hdr = session.auth_header_name.strip()
                if eff_auth_hdr and eff_auth_hdr.lower() != "authorization":
                    if not any(k.lower() == eff_auth_hdr.lower() for k in auth_headers):
                        auth_headers[eff_auth_hdr] = f"{session.auth_header_prefix}{session.access_token}"
                elif not any(k.lower() == "authorization" for k in auth_headers):
                    auth_headers["Authorization"] = f"Bearer {session.access_token}"
            if session.csrf_token and not any(k.lower() in _CSRF_HEADER_NAMES for k in auth_headers):
                auth_headers[session.csrf_header_name or "X-CSRF-Token"] = session.csrf_token
            state: dict[str, Any] = {"cookies": cookies, "headers": auth_headers}
            if session.local_storage:
                state["local_storage"] = dict(session.local_storage)
            return state


def _get_raw_socket(raw_stream: Any) -> Any:
    """Best-effort unwrap of the underlying socket from a urllib3/http.client stream."""
    for attr in ("_connection", "connection"):
        conn = getattr(raw_stream, attr, None)
        sock = getattr(conn, "sock", None)
        if sock is not None and callable(getattr(sock, "settimeout", None)):
            return sock
    fp = getattr(raw_stream, "_fp", None)
    fp_inner = getattr(fp, "fp", None)
    raw_sock = getattr(getattr(fp_inner, "raw", None), "_sock", None)
    if raw_sock is not None and callable(getattr(raw_sock, "settimeout", None)):
        return raw_sock
    return None


def _read_sse_bounded(
    resp: Any,
    max_bytes: int = _SSE_DEFAULT_MAX_BYTES,
    max_duration_s: float = _SSE_DEFAULT_MAX_DURATION_S,
) -> bytes:
    """Read an open-ended text/event-stream response up to byte or wall-time bounds.

    Captures an initial event preview without hanging until the full HTTP timeout
    and closes unfinished streams cleanly so status remains intact (e.g. 200).
    """
    cap = max(0, int(max_bytes))
    dur = max(0.01, float(max_duration_s))
    raw = getattr(resp, "raw", None)
    if raw is None or cap == 0:
        return b""

    buf = bytearray()
    deadline = time.monotonic() + dur
    sock = _get_raw_socket(raw)
    orig_timeout: float | None = None
    if sock is not None:
        try:
            orig_timeout = sock.gettimeout()
        except OSError:
            orig_timeout = None

    eof_reached = False
    timed_out = False
    timeout_exc_types: tuple[type[BaseException], ...] = (
        TimeoutError,
        socket.timeout,
        requests.exceptions.ReadTimeout,
        urllib3_exceptions.ReadTimeoutError,
        urllib3_exceptions.TimeoutError,
    )

    try:
        is_chunked = bool(getattr(raw, "chunked", False))
        supports_chunked = callable(getattr(raw, "supports_chunked_reads", None)) and raw.supports_chunked_reads()
        if is_chunked and supports_chunked and callable(getattr(raw, "read_chunked", None)):
            if sock is not None:
                try:
                    sock.settimeout(max(0.01, deadline - time.monotonic()))
                except OSError:
                    pass
            for chunk in raw.read_chunked(amt=min(4096, cap), decode_content=False):
                if not chunk:
                    break
                take = cap - len(buf)
                if len(chunk) >= take:
                    buf.extend(chunk[:take])
                    break
                buf.extend(chunk)
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    break
                if sock is not None:
                    try:
                        sock.settimeout(max(0.01, remaining))
                    except OSError:
                        pass
            else:
                eof_reached = True
        else:
            read_fn = getattr(raw, "read1", None) or getattr(raw, "read", None)
            if callable(read_fn):
                while len(buf) < cap:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    if sock is not None:
                        try:
                            sock.settimeout(max(0.01, remaining))
                        except OSError:
                            pass
                    to_read = min(4096, cap - len(buf))
                    try:
                        chunk = read_fn(to_read, decode_content=False)
                    except TypeError:
                        chunk = read_fn(to_read)
                    if not chunk:
                        eof_reached = True
                        break
                    take = cap - len(buf)
                    buf.extend(chunk[:take])
    except timeout_exc_types:
        timed_out = True
    except (urllib3_exceptions.ProtocolError, OSError):
        # Partial stream close / reset after headers were received -> keep captured bytes.
        pass
    finally:
        if eof_reached and not timed_out and sock is not None:
            try:
                sock.settimeout(orig_timeout)
            except OSError:
                pass
        else:
            close_raw = getattr(raw, "close", None)
            if callable(close_raw):
                try:
                    close_raw()
                except Exception:
                    pass

    return bytes(buf)


def _decode_raw_response(raw_bytes: bytes, content_encoding: str) -> bytes:
    """Best-effort decompression that survives mismatched gzip headers."""
    enc = (content_encoding or "").strip().lower()
    if enc == "gzip":
        try:
            return gzip.decompress(raw_bytes)
        except (OSError, EOFError, zlib.error):
            return raw_bytes
    if enc == "deflate":
        try:
            return zlib.decompress(raw_bytes)
        except zlib.error:
            try:
                return zlib.decompress(raw_bytes, -zlib.MAX_WBITS)
            except zlib.error:
                return raw_bytes
    return raw_bytes


def _sanitize_multipart_header_value(raw: str, *, label: str) -> str:
    """Validate and strip CR/LF from multipart header metadata, rejecting NUL bytes."""
    if "\x00" in raw:
        raise ValueError(f"multipart {label} must not contain NUL bytes")
    return raw.replace("\r", "").replace("\n", "")


def _encode_multipart_form_data(
    files: Sequence[dict[str, Any]],
    form_fields: dict[str, Any] | None = None,
) -> tuple[bytes, str, str]:
    """Encode files and optional form fields as RFC 7578 multipart/form-data.

    Returns ``(body_bytes, content_type_header, body_preview)`` where ``body_preview``
    is a compact summary string that never dumps raw binary bytes into receipts.
    """
    if isinstance(files, (str, bytes, bytearray, dict)) or not isinstance(files, Sequence):
        raise ValueError("files must be a list of file objects")
    if len(files) == 0:
        raise ValueError("files must contain at least one file entry")
    if len(files) > _MULTIPART_MAX_FILES:
        raise ValueError(
            f"multipart files count {len(files)} exceeds limit of {_MULTIPART_MAX_FILES}"
        )
    if form_fields is not None and not isinstance(form_fields, dict):
        raise ValueError("form_fields must be a dict when used with multipart files")

    boundary = f"----kryonBoundary{uuid.uuid4().hex}"
    boundary_bytes = boundary.encode("ascii")
    closing = b"--" + boundary_bytes + b"--\r\n"

    parts: list[bytes] = []
    total_size = len(closing)
    form_field_names: list[str] = []
    file_summaries: list[dict[str, Any]] = []

    if form_fields:
        for raw_k, raw_v in form_fields.items():
            clean_key = _sanitize_multipart_header_value(str(raw_k), label="form field name").strip()
            if not clean_key:
                raise ValueError("multipart form field name must not be empty")
            escaped_key = clean_key.replace('"', '\\"')
            val_bytes = ("" if raw_v is None else str(raw_v)).encode("utf-8")
            part = (
                b"--" + boundary_bytes + b"\r\n"
                + f'Content-Disposition: form-data; name="{escaped_key}"\r\n\r\n'.encode("utf-8")
                + val_bytes + b"\r\n"
            )
            total_size += len(part)
            if total_size > _MULTIPART_MAX_TOTAL_BYTES:
                raise ValueError(
                    f"multipart payload size {total_size} exceeds total limit of {_MULTIPART_MAX_TOTAL_BYTES} bytes"
                )
            parts.append(part)
            form_field_names.append(clean_key)

    for idx, item in enumerate(files):
        if not isinstance(item, dict):
            raise ValueError(f"multipart file entry at index {idx} must be a dict")
        raw_field = "file" if item.get("field") is None else str(item["field"])
        clean_field = _sanitize_multipart_header_value(raw_field, label="field").strip() or "file"
        escaped_field = clean_field.replace('"', '\\"')

        raw_filename = "upload.bin" if item.get("filename") is None else str(item["filename"])
        clean_filename = _sanitize_multipart_header_value(raw_filename, label="filename")
        if not clean_filename.strip():
            clean_filename = "upload.bin"
        escaped_filename = clean_filename.replace('"', '\\"')

        raw_ct = "application/octet-stream" if item.get("content_type") is None else str(item["content_type"])
        clean_ct = _sanitize_multipart_header_value(raw_ct, label="content_type").strip() or "application/octet-stream"

        has_text = item.get("content") is not None
        has_b64 = item.get("content_base64") is not None
        if has_text and has_b64:
            raise ValueError(
                f"multipart file entry at index {idx} cannot specify both 'content' and 'content_base64'"
            )
        if has_b64:
            b64_val = item["content_base64"]
            if not isinstance(b64_val, str):
                raise ValueError(f"multipart file entry at index {idx} content_base64 must be a string")
            compact_b64 = "".join(b64_val.split())
            if len(compact_b64) > ((_MULTIPART_MAX_FILE_BYTES + 3) * 4 // 3) + 4:
                raise ValueError(
                    f"multipart file {clean_filename!r} exceeds per-file limit of {_MULTIPART_MAX_FILE_BYTES} bytes"
                )
            try:
                file_bytes = base64.b64decode(compact_b64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ValueError(
                    f"invalid base64 in multipart file {clean_filename!r}: {exc}"
                ) from exc
        elif has_text:
            raw_content = item["content"]
            if isinstance(raw_content, (bytes, bytearray)):
                file_bytes = bytes(raw_content)
            else:
                file_bytes = str(raw_content).encode("utf-8")
        else:
            file_bytes = b""

        if len(file_bytes) > _MULTIPART_MAX_FILE_BYTES:
            raise ValueError(
                f"multipart file {clean_filename!r} size {len(file_bytes)} "
                f"exceeds per-file limit of {_MULTIPART_MAX_FILE_BYTES} bytes"
            )

        part = (
            b"--" + boundary_bytes + b"\r\n"
            + f'Content-Disposition: form-data; name="{escaped_field}"; filename="{escaped_filename}"\r\n'.encode("utf-8")
            + f"Content-Type: {clean_ct}\r\n\r\n".encode("utf-8")
            + file_bytes + b"\r\n"
        )
        total_size += len(part)
        if total_size > _MULTIPART_MAX_TOTAL_BYTES:
            raise ValueError(
                f"multipart payload size {total_size} exceeds total limit of {_MULTIPART_MAX_TOTAL_BYTES} bytes"
            )
        parts.append(part)
        file_summaries.append({
            "field": clean_field,
            "filename": clean_filename,
            "content_type": clean_ct,
            "bytes": len(file_bytes),
        })

    parts.append(closing)
    body_bytes = b"".join(parts)
    preview_doc: dict[str, Any] = {"files": file_summaries}
    if form_field_names:
        preview_doc["fields"] = form_field_names
    body_preview = f"multipart/form-data {json.dumps(preview_doc, ensure_ascii=False, separators=(',', ':'))}"
    return body_bytes, f"multipart/form-data; boundary={boundary}", body_preview


class AgenticHTTPClient:
    """Scope-locked, WireBudget-accounted HTTP/WS client with dedup, pacing, and auto re-auth."""

    def __init__(
        self,
        *,
        base_url: str,
        receipt_store: ReceiptStore,
        actors: ActorManager | None = None,
        allowed_methods: Sequence[str] = ("GET", "HEAD"),
        max_requests: int = 300,
        wire_budget: WireBudget | None = None,
        timeout_s: float = 15.0,
        max_response_bytes: int = 4 * 1024 * 1024,
        excluded_paths: Sequence[str] = (),
        in_scope_assets: Sequence[str] = (),
        out_of_scope_assets: Sequence[str] = (),
        max_degradation_streak: int = 5,
        max_rps: float = 0.0,
        allow_lifecycle_routes: bool = False,
        max_retry_after_s: float = _DEFAULT_MAX_RETRY_AFTER_S,
        max_rate_limit_retries: int = _MAX_RATE_LIMIT_RETRIES,
        deadline_monotonic: float | None = None,
        custom_headers: dict[str, Any] | Sequence[str] | None = None,
        _sleep_fn: Callable[[float], None] | None = None,
        _monotonic_fn: Callable[[], float] | None = None,
    ):
        if isinstance(max_rps, bool):
            raise ValueError("max_rps must be a finite number >= 0.0")
        eff_max_rps = float(max_rps)
        if not math.isfinite(eff_max_rps) or eff_max_rps < 0.0:
            raise ValueError(f"max_rps must be a finite number >= 0.0, got {max_rps!r}")

        self.base_url = normalize_origin(base_url)
        parsed_origin = urlsplit(self.base_url)
        self._origin = (parsed_origin.scheme, parsed_origin.netloc)
        self.allow_lifecycle_routes: bool = bool(allow_lifecycle_routes)
        self.scope_guard = ScopeGuard(
            self.base_url,
            tuple(excluded_paths or ()),
            allow_lifecycle_routes=self.allow_lifecycle_routes,
            in_scope_assets=tuple(in_scope_assets or ()),
            out_of_scope_assets=tuple(out_of_scope_assets or ()),
        )
        self.excluded_paths: tuple[str, ...] = self.scope_guard.excluded_paths
        self.in_scope_assets: tuple[str, ...] = self.scope_guard.in_scope_assets
        self.out_of_scope_assets: tuple[str, ...] = self.scope_guard.out_of_scope_assets
        self.max_degradation_streak: int = max(0, int(max_degradation_streak))
        self._degradation_streak: int = 0
        self.max_rps: float = eff_max_rps
        self.max_retry_after_s: float = max(0.0, float(max_retry_after_s))
        self.max_rate_limit_retries: int = max(0, int(max_rate_limit_retries))
        self.deadline_monotonic: float | None = (
            None if deadline_monotonic is None else float(deadline_monotonic)
        )
        self._sleep_fn: Callable[[float], None] = _sleep_fn or time.sleep
        self._monotonic_fn: Callable[[], float] = _monotonic_fn or time.monotonic
        self._rate_lock = threading.Lock()
        self._next_allowed_at: float | None = None
        self._adaptive_delay_s: float = 0.0
        self._adaptive_healthy_streak: int = 0
        self._last_wire_at: float | None = None
        self.receipt_store = receipt_store
        self.actors = actors or ActorManager(global_headers=parse_custom_headers(custom_headers))
        if actors is not None and custom_headers:
            self.actors.set_global_headers(custom_headers)
        self.allowed_methods = frozenset(
            str(m).strip().upper() for m in allowed_methods if str(m).strip()
        ) or frozenset({"GET"})
        self.budget = wire_budget or WireBudget(int(max_requests), uuid.uuid4().hex)
        self.timeout_s = float(timeout_s)
        self.max_response_bytes = int(max_response_bytes)
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        self._cache: dict[tuple[Any, ...], dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._auth_lock = threading.RLock()
        self._in_session_refresh: bool = False
        self._refresh_already_attempted: bool = False

    def _acquire_rate_limit_slot(self, *, skip_adaptive: bool = False) -> None:
        """Pace live wire calls monotonically using max_rps and adaptive 429 delay."""
        rps_wait_s = 0.0
        adaptive_wait_s = 0.0
        with self._rate_lock:
            now = float(self._monotonic_fn())
            if self.max_rps > 0.0:
                interval = 1.0 / self.max_rps
                if self._next_allowed_at is None or now >= self._next_allowed_at:
                    scheduled = now
                else:
                    scheduled = self._next_allowed_at
                self._next_allowed_at = scheduled + interval
                rps_wait_s = max(0.0, scheduled - now)
            if not skip_adaptive and self._adaptive_delay_s > 0.0 and self._last_wire_at is not None:
                elapsed = max(0.0, now - self._last_wire_at)
                adaptive_wait_s = max(0.0, self._adaptive_delay_s - elapsed)
        wait_s = max(rps_wait_s, adaptive_wait_s)
        if wait_s > 0.0:
            self._sleep_fn(wait_s)

    def _update_adaptive_pacing(self, *, status: int, retry_after_s: float | None = None) -> None:
        """Increase adaptive delay after rate-limit signals and decay smoothly on consecutive 2xx/3xx."""
        with self._rate_lock:
            if status == 429 or (status == 503 and retry_after_s is not None):
                self._adaptive_healthy_streak = 0
                if self._adaptive_delay_s <= 0.0:
                    hint = (
                        retry_after_s * 0.25
                        if (retry_after_s is not None and retry_after_s > 0.0)
                        else _ADAPTIVE_DELAY_MIN_S
                    )
                    self._adaptive_delay_s = min(_ADAPTIVE_DELAY_MAX_S, max(_ADAPTIVE_DELAY_MIN_S, hint))
                else:
                    self._adaptive_delay_s = min(
                        _ADAPTIVE_DELAY_MAX_S,
                        max(self._adaptive_delay_s * 1.5, self._adaptive_delay_s + 0.2),
                    )
            elif 200 <= status < 400:
                if self._adaptive_delay_s > 0.0:
                    self._adaptive_healthy_streak += 1
                    if self._adaptive_healthy_streak >= _ADAPTIVE_HEALTHY_STREAK_FOR_DECAY:
                        decayed = self._adaptive_delay_s * _ADAPTIVE_DECAY_FACTOR
                        if decayed < _ADAPTIVE_DECAY_FLOOR_S:
                            self._adaptive_delay_s = 0.0
                            self._adaptive_healthy_streak = 0
                        else:
                            self._adaptive_delay_s = decayed

    def _get_session(self) -> requests.Session:
        sess = getattr(self._thread_local, "session", None)
        if sess is None:
            sess = requests.Session()
            sess.trust_env = False
            sess.headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
            self._thread_local.session = sess
            with self._sessions_lock:
                self._sessions.append(sess)
        return sess

    def close(self) -> None:
        with self._sessions_lock:
            sessions = list(self._sessions)
            self._sessions.clear()
        for sess in sessions:
            try:
                sess.close()
            except Exception:
                pass
        if hasattr(self._thread_local, "session"):
            try:
                delattr(self._thread_local, "session")
            except AttributeError:
                pass

    def resolve_in_scope(
        self,
        url_or_path: str,
        *,
        allow_websocket: bool = True,
        allow_lifecycle_routes: bool | None = None,
    ) -> tuple[str, str, str]:
        """Resolve relative path or URL and verify exact origin match, excluded paths, and lifecycle guards."""
        raw = str(url_or_path or "").strip()
        if not raw:
            raise ScopeViolationError("URL is required")
        if raw.startswith("//"):
            raise ScopeViolationError(f"scheme-relative cross-origin URL blocked: {raw}")
        if any(ch in raw for ch in ("\x00", "\r", "\n")):
            raise ScopeViolationError(f"URL contains control characters: {raw!r}")

        eff_allow_lifecycle = (
            self.allow_lifecycle_routes
            if allow_lifecycle_routes is None
            else bool(allow_lifecycle_routes)
        )

        lower_raw = raw.lower()
        if lower_raw.startswith(("ws://", "wss://")):
            if not allow_websocket:
                raise ScopeViolationError(
                    f"WebSocket URL not allowed in HTTP context: {raw!r}"
                )
            parsed_ws = urlsplit(raw)
            ws_scheme = parsed_ws.scheme.lower()
            if parsed_ws.username is not None or parsed_ws.password is not None or "@" in parsed_ws.netloc:
                raise ScopeViolationError(f"WebSocket URL must not embed credentials: {raw!r}")
            expected_http_scheme = "http" if ws_scheme == "ws" else "https"
            ws_host = (parsed_ws.hostname or "").strip().lower().rstrip(".")
            default_port = 443 if ws_scheme == "wss" else 80
            try:
                ws_port = parsed_ws.port if parsed_ws.port is not None else default_port
            except ValueError as exc:
                raise ScopeViolationError(f"invalid WebSocket port in {raw!r}") from exc
            if not self.scope_guard.check_origin(expected_http_scheme, ws_host, ws_port):
                raise ScopeViolationError(
                    f"out-of-scope WebSocket URL {raw!r}; allowed origin is {self.base_url}"
                )
            ws_path = parsed_ws.path or "/"
            equiv_http_url = urlunsplit((expected_http_scheme, parsed_ws.netloc, ws_path, parsed_ws.query, ""))
            try:
                self.scope_guard.check_url(
                    equiv_http_url,
                    allow_lifecycle_routes=eff_allow_lifecycle,
                )
            except ValueError as exc:
                raise ScopeViolationError(str(exc)) from exc
            clean_ws_url = urlunsplit((ws_scheme, parsed_ws.netloc, ws_path, parsed_ws.query, ""))
            return clean_ws_url, ws_path, parsed_ws.query

        resolved = urljoin(self.base_url, raw)
        parsed = urlsplit(resolved)
        raw_clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        try:
            self.scope_guard.check_url(
                raw_clean_url,
                allow_lifecycle_routes=eff_allow_lifecycle,
            )
        except ValueError as exc:
            raise ScopeViolationError(str(exc)) from exc
        host_norm = (parsed.hostname or "").strip().lower().rstrip(".")
        host_part = f"[{host_norm}]" if ":" in host_norm else host_norm
        netloc_norm = f"{host_part}:{parsed.port}" if parsed.port is not None else host_part
        clean_url = urlunsplit((parsed.scheme.lower(), netloc_norm, parsed.path or "/", parsed.query, ""))
        return clean_url, parsed.path or "/", parsed.query

    def _merge_query(
        self,
        url: str,
        query_params: dict[str, Any] | None,
        *,
        allow_websocket: bool = True,
        allow_lifecycle_routes: bool | None = None,
    ) -> tuple[str, str, str]:
        if not query_params:
            return self.resolve_in_scope(
                url,
                allow_websocket=allow_websocket,
                allow_lifecycle_routes=allow_lifecycle_routes,
            )
        clean_url, _, _ = self.resolve_in_scope(
            url,
            allow_websocket=allow_websocket,
            allow_lifecycle_routes=allow_lifecycle_routes,
        )
        parsed = urlsplit(clean_url)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        for k, v in query_params.items():
            if v is None:
                existing.pop(str(k), None)
            else:
                existing[str(k)] = str(v)
        new_query = urlencode(sorted(existing.items()))
        rebuilt = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_query, ""))
        return self.resolve_in_scope(
            rebuilt,
            allow_websocket=allow_websocket,
            allow_lifecycle_routes=allow_lifecycle_routes,
        )

    def register_discovered_auth_header(self, header_name: str, prefix: str = "") -> str:
        """Store a preferred non-Authorization API token header on ActorManager."""
        return self.actors.register_discovered_auth_header(header_name, prefix=prefix)

    def _maybe_register_openapi_auth_header(
        self,
        *,
        status: int,
        content_type: str,
        body_text: str,
    ) -> None:
        if not (200 <= status < 300) or not body_text or len(body_text) > 2_000_000:
            return
        if self.actors.discovered_auth_header:
            return
        if "json" not in content_type and not body_text.lstrip().startswith("{"):
            return
        if '"securitySchemes"' not in body_text and '"securityDefinitions"' not in body_text:
            return
        try:
            parsed = json.loads(body_text)
        except ValueError:
            return
        if not isinstance(parsed, dict):
            return
        for hdr_name in extract_openapi_header_auth_names(parsed):
            if hdr_name.lower() != "authorization":
                registered = self.actors.register_discovered_auth_header(hdr_name)
                if registered:
                    return

    def _check_actor_logout_guard(
        self,
        *,
        path: str,
        actor: str,
        session: ActorSession,
        extra_headers: dict[str, str],
        allow_lifecycle_routes: bool,
    ) -> None:
        """Prevent shared authenticated actors from accidentally invalidating their own session."""
        if allow_lifecycle_routes or actor == "anon":
            return
        with session._lock:
            is_active_or_provisioned = bool(session.authenticated or session.login_payload)
            actor_auth_hdr = session.auth_header_name.strip().lower()
        auth_override_keys = set(_AUTH_OVERRIDE_HEADERS)
        if actor_auth_hdr:
            auth_override_keys.add(actor_auth_hdr)
        has_explicit_auth_override = any(
            k.strip().lower() in auth_override_keys and str(v).strip()
            for k, v in extra_headers.items()
        )
        if has_explicit_auth_override:
            return
        if not is_active_or_provisioned:
            return
        matched_logout = match_logout_route(path)
        if matched_logout is not None:
            raise ScopeViolationError(
                f"active authenticated actor logout route blocked: {path!r} for actor {actor!r} "
                f"(matched segment {matched_logout!r}); invoking logout under the shared actor "
                "session would invalidate that actor for other shards — test logout using "
                "actor='anon' or an explicit Authorization/Cookie headers override instead"
            )

    def _record_degradation_status(self, *, status: int, url: str) -> None:
        """Track consecutive degraded/unreachable responses (status=0 or 429/502/503/504) and stop gracefully."""
        if self.max_degradation_streak <= 0 or status < 0:
            return
        streak = 0
        with self._lock:
            if status == 0 or status in _DEGRADATION_STATUS_CODES:
                self._degradation_streak += 1
                streak = self._degradation_streak
            else:
                self._degradation_streak = 0
        if streak >= self.max_degradation_streak:
            raise ServiceDegradationError(
                f"target service degradation detected after {streak} consecutive "
                f"degraded/unreachable responses (status={status}, url={url})"
            )

    def _send_wire(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body_bytes: bytes | None,
        body_preview: str,
        record_receipt: bool = True,
        save_session_as: str = "",
        auth_header_name: str = "",
        out_cookies: dict[str, str] | None = None,
        record_degradation: bool = True,
        skip_adaptive_pacing: bool = False,
    ) -> dict[str, Any]:
        allowed, reason = self.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        self._acquire_rate_limit_slot(skip_adaptive=skip_adaptive_pacing)

        wire_headers = dict(headers)
        if not any(k.lower() == "user-agent" for k in wire_headers):
            wire_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT

        started = time.monotonic()
        status = 0
        resp_headers: dict[str, str] = {}
        raw_bytes = b""
        text = ""
        content_type = ""
        redirect_location = ""
        error = ""
        saved_session_meta: dict[str, Any] | None = None

        try:
            # Clear thread-local session cookie jar before & after each wire call so per-actor
            # cookies (managed strictly via ActorSession.build_headers) never leak across actors.
            http_session = self._get_session()
            http_session.cookies.clear()
            # Read raw stream directly so mismatched Content-Encoding never crashes requests.
            resp = http_session.request(
                method=method,
                url=url,
                headers=wire_headers,
                data=body_bytes,
                allow_redirects=False,
                timeout=self.timeout_s,
                stream=True,
            )
            try:
                status = int(resp.status_code)
                resp_headers = {str(k): str(v) for k, v in resp.headers.items()}
                content_type = resp_headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                redirect_location = resp_headers.get("Location", "")
                if content_type == "text/event-stream":
                    raw_stream = _read_sse_bounded(
                        resp,
                        max_bytes=min(_SSE_DEFAULT_MAX_BYTES, self.max_response_bytes),
                        max_duration_s=min(_SSE_DEFAULT_MAX_DURATION_S, max(0.05, self.timeout_s)),
                    )
                else:
                    raw_stream = resp.raw.read(self.max_response_bytes + 1, decode_content=False)
                    if len(raw_stream) > self.max_response_bytes:
                        raw_stream = raw_stream[: self.max_response_bytes]
                raw_bytes = _decode_raw_response(raw_stream, resp_headers.get("Content-Encoding", ""))
                if is_grpc_web_content_type(content_type):
                    decoded_grpc = decode_grpc_web_frames(raw_bytes, content_type=content_type)
                    text = json.dumps(decoded_grpc, ensure_ascii=False)
                else:
                    text = raw_bytes.decode("utf-8", errors="replace")
                cookies = {c.name: c.value for c in resp.cookies}
                if not cookies and "Set-Cookie" in resp_headers:
                    for part in resp_headers["Set-Cookie"].split(","):
                        nv = part.strip().split(";", 1)[0]
                        if "=" in nv:
                            ck, cv = nv.split("=", 1)
                            if ck.strip() and cv.strip() and ck.strip().lower() not in {"path", "expires", "max-age", "domain", "samesite"}:
                                cookies[ck.strip()] = cv.strip()
                if out_cookies is not None and cookies:
                    out_cookies.update(cookies)
                http_session.cookies.clear()
                clean_save_alias = str(save_session_as or "").strip()
                if clean_save_alias and clean_save_alias != "anon" and 200 <= status < 400:
                    (
                        cap_cookies,
                        cap_bearer,
                        cap_refresh,
                        cap_csrf,
                        cap_csrf_header,
                        cap_csrf_field,
                        cap_auth_header,
                        cap_token_source,
                    ) = _extract_session_material_full(
                        headers=resp_headers,
                        cookies=cookies,
                        body_text=text,
                    )
                    if cap_cookies or cap_bearer or cap_csrf:
                        explicit_auth_hdr = _validate_auth_header_name(auth_header_name, strict=False)
                        disc_auth_hdr, disc_auth_pfx = self.actors.get_discovered_auth_header()
                        if cap_bearer:
                            if explicit_auth_hdr:
                                resolved_auth_hdr = explicit_auth_hdr
                                resolved_auth_pfx = ""
                            elif cap_auth_header:
                                resolved_auth_hdr = cap_auth_header
                                resolved_auth_pfx = ""
                            elif cap_token_source == "json_body" and disc_auth_hdr:
                                resolved_auth_hdr = disc_auth_hdr
                                resolved_auth_pfx = disc_auth_pfx
                            else:
                                resolved_auth_hdr = ""
                                resolved_auth_pfx = ""
                        else:
                            resolved_auth_hdr = explicit_auth_hdr
                            resolved_auth_pfx = ""
                        dyn = self.actors.register_dynamic_session(
                            clean_save_alias,
                            cookies=cap_cookies,
                            bearer_token=cap_bearer,
                            refresh_token=cap_refresh,
                            csrf_token=cap_csrf,
                            csrf_header_name=cap_csrf_header,
                            csrf_field_name=cap_csrf_field,
                            auth_header_name=resolved_auth_hdr,
                            auth_header_prefix=resolved_auth_pfx,
                        )
                        saved_session_meta = {
                            "alias": dyn.alias,
                            "role": dyn.role,
                            "authenticated": dyn.authenticated,
                            "has_cookies": bool(dyn.cookies),
                            "has_bearer": bool(dyn.access_token),
                            "has_csrf": bool(dyn.csrf_token),
                        }
                        if dyn.auth_header_name:
                            saved_session_meta["auth_header"] = dyn.auth_header_name
                elif not clean_save_alias:
                    self.actors.update_from_response(
                        actor, headers=resp_headers, cookies=cookies, body_text=text
                    )
                    if record_receipt:
                        self._maybe_register_openapi_auth_header(
                            status=status,
                            content_type=content_type,
                            body_text=text,
                        )
            finally:
                http_session.cookies.clear()
                resp.close()
        except Exception as exc:
            error = f"{type(exc).__name__}: {str(exc)[:200]}"
        finally:
            with self._rate_lock:
                self._last_wire_at = float(self._monotonic_fn())

        elapsed_ms = (time.monotonic() - started) * 1000.0
        if not record_receipt:
            if record_degradation:
                self._record_degradation_status(status=int(status), url=str(url))
            graphql_has_errors = False
            stripped_body = text.lstrip()
            if stripped_body.startswith("{"):
                try:
                    parsed_auth = json.loads(text)
                except ValueError:
                    parsed_auth = None
                if isinstance(parsed_auth, dict) and isinstance(parsed_auth.get("errors"), list) and parsed_auth["errors"]:
                    graphql_has_errors = True
            return {
                "receipt_id": "",
                "actor": str(actor or "anon"),
                "method": str(method or "GET").upper(),
                "url": str(url),
                "path": str(path or "/"),
                "query": str(query or ""),
                "status": int(status),
                "elapsed_ms": round(float(elapsed_ms), 2),
                "content_type": str(content_type or ""),
                "response_length": len(raw_bytes),
                "redirect_location": redirect_location,
                "body": "",
                "error": str(error or ""),
                "_body_mentions_csrf": "csrf" in text.lower(),
                "_graphql_has_errors": graphql_has_errors,
            }
        extra_sensitive_hdrs = self.actors.sensitive_header_names()
        rec = self.receipt_store.record(
            actor=actor,
            method=method,
            url=url,
            path=path,
            query=query,
            request_headers=_redact_extra_sensitive_headers(wire_headers, extra_sensitive_hdrs),
            request_body=body_preview,
            status=status,
            elapsed_ms=elapsed_ms,
            content_type=content_type,
            response_headers=_redact_extra_sensitive_headers(resp_headers, extra_sensitive_hdrs),
            redirect_location=redirect_location,
            raw_response_bytes=raw_bytes,
            response_text=text,
            error=error,
            secret_values=self.actors.all_secrets(),
        )
        if saved_session_meta is not None:
            self.actors.set_source_receipt_id(saved_session_meta["alias"], rec["receipt_id"])
            saved_session_meta["source_receipt_id"] = rec["receipt_id"]
            rec = dict(rec)
            rec["saved_session"] = saved_session_meta
        if record_degradation:
            self._record_degradation_status(status=int(status), url=str(url))
        return rec

    def _send_wire_with_rate_limit_retry(
        self,
        *,
        actor: str,
        method: str,
        url: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body_bytes: bytes | None,
        body_preview: str,
        save_session_as: str = "",
        auth_header_name: str = "",
        out_cookies: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send wire request with bounded 429/503 Retry-After backoff, adaptive pacing, and degradation accounting."""
        receipt: dict[str, Any] = {}
        for attempt in range(self.max_rate_limit_retries + 1):
            receipt = self._send_wire(
                actor=actor,
                method=method,
                url=url,
                path=path,
                query=query,
                headers=headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
                save_session_as=save_session_as,
                auth_header_name=auth_header_name,
                out_cookies=out_cookies,
                record_degradation=False,
                skip_adaptive_pacing=(attempt > 0),
            )
            status = int(receipt["status"])
            retry_after_s = _parse_retry_after_seconds(
                receipt.get("response_headers"),
                max_retry_after_s=self.max_retry_after_s,
            )
            is_retryable = status == 429 or (status == 503 and retry_after_s is not None)
            if is_retryable:
                self._update_adaptive_pacing(status=status, retry_after_s=retry_after_s)
            elif 200 <= status < 400:
                self._update_adaptive_pacing(status=status, retry_after_s=None)
            if (
                not is_retryable
                or attempt >= self.max_rate_limit_retries
                or self._budget_remaining() <= 4
            ):
                break
            if retry_after_s is not None:
                delay_s = retry_after_s
            else:
                base_delay = _RATE_LIMIT_FALLBACK_BASE_S * (2 ** attempt)
                delay_s = min(self.max_retry_after_s, base_delay * random.uniform(0.85, 1.15))
            if self.deadline_monotonic is not None:
                remaining_wall = self.deadline_monotonic - float(self._monotonic_fn())
                if remaining_wall <= delay_s:
                    break
            if delay_s > 0.0:
                self._sleep_fn(delay_s)
            if out_cookies is not None:
                out_cookies.clear()

        self._record_degradation_status(status=int(receipt["status"]), url=str(url))
        return receipt

    def _send_websocket_wire(
        self,
        *,
        actor: str,
        url: str,
        path: str,
        query: str,
        headers: dict[str, str],
        send_messages: Sequence[str] | None,
        body_preview: str,
    ) -> dict[str, Any]:
        """Execute a scope-verified, budgeted, rate-limited RFC-6455 WebSocket probe."""
        allowed, reason = self.budget.consume()
        if not allowed:
            raise BudgetExhaustedError(reason)

        self._acquire_rate_limit_slot()

        wire_headers = dict(headers)
        if not any(k.lower() == "user-agent" for k in wire_headers):
            wire_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT
        if not any(k.lower() == "origin" for k in wire_headers):
            wire_headers["Origin"] = self.base_url.rstrip("/")

        started = time.monotonic()
        ws_result = probe_websocket(
            url,
            headers=wire_headers,
            send_messages=send_messages,
            timeout_s=min(self.timeout_s, 5.0),
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0

        status = int(ws_result.get("status") or 0)
        resp_headers = ws_result.get("response_headers")
        if not isinstance(resp_headers, dict):
            resp_headers = {}
        err_text = str(ws_result.get("error") or "")
        summary_doc = {
            "upgraded": bool(ws_result.get("upgraded")),
            "frames_received": ws_result.get("frames_received") or [],
            "close_code": ws_result.get("close_code"),
            "error": err_text,
        }
        summary_text = json.dumps(summary_doc, ensure_ascii=False)
        summary_bytes = summary_text.encode("utf-8")

        extra_sensitive_hdrs = self.actors.sensitive_header_names()
        rec = self.receipt_store.record(
            actor=actor,
            method="WS",
            url=url,
            path=path,
            query=query,
            request_headers=_redact_extra_sensitive_headers(wire_headers, extra_sensitive_hdrs),
            request_body=body_preview,
            status=status,
            elapsed_ms=elapsed_ms,
            content_type="application/json",
            response_headers=_redact_extra_sensitive_headers(
                {str(k): str(v) for k, v in resp_headers.items()},
                extra_sensitive_hdrs,
            ),
            redirect_location="",
            raw_response_bytes=summary_bytes,
            response_text=summary_text,
            error=err_text,
            secret_values=self.actors.all_secrets(),
        )
        self._record_degradation_status(status=status, url=url)
        return rec

    def _budget_remaining(self) -> int:
        lock = getattr(self.budget, "_lock", None)
        if lock is not None:
            with lock:
                return int(self.budget.limit - self.budget.used)
        return int(self.budget.limit - self.budget.used)

    def authenticate_actor(self, alias: str, *, force_login: bool = False) -> bool:
        """Sign in an actor via configured login_path if not yet authenticated."""
        session = self.actors.get(alias)
        if alias == "anon":
            return True
        with self._auth_lock:
            with session._lock:
                already_auth = session.authenticated
                refresh_tok = session.refresh_token
                actor_refresh_path = session.refresh_path
                login_payload = dict(session.login_payload)
                login_graphql_query = session.login_graphql_query
            if already_auth and not force_login:
                return True
            # Try refresh endpoint first if refresh_token exists and force_login was requested.
            eff_refresh_path = actor_refresh_path or self.actors.refresh_path
            if force_login and not self._refresh_already_attempted and refresh_tok and eff_refresh_path:
                try:
                    r_url, r_path, r_query = self.resolve_in_scope(eff_refresh_path, allow_websocket=False)
                    r_body = json.dumps({"refresh_token": refresh_tok}).encode("utf-8")
                    r_headers = session.build_headers("POST", {"Content-Type": "application/json"})
                    receipt = self._send_wire(
                        actor=alias,
                        method="POST",
                        url=r_url,
                        path=r_path,
                        query=r_query,
                        headers=r_headers,
                        body_bytes=r_body,
                        body_preview='{"refresh_token":"<REDACTED>"}',
                        record_receipt=False,
                    )
                    if 200 <= receipt["status"] < 300:
                        with session._lock:
                            session.last_auth_status = int(receipt["status"])
                            session.last_auth_path = r_path
                            session.last_auth_error = ""
                            session.authenticated = True
                        return True
                except (BudgetExhaustedError, ServiceDegradationError):
                    raise
                except Exception:
                    pass

            if not login_payload:
                with session._lock:
                    return session.authenticated
            try:
                login_url, login_path, login_query = self.resolve_in_scope(self.actors.login_path)
            except ScopeViolationError as exc:
                with session._lock:
                    session.last_auth_status = None
                    session.last_auth_path = str(self.actors.login_path)
                    session.last_auth_error = str(exc)[:200]
                raise
            redacted_vars = {k: ("<REDACTED>" if k == "password" else v) for k, v in login_payload.items()}
            active_content_type = "application/json"
            if login_graphql_query:
                active_body_bytes = json.dumps(
                    {"query": login_graphql_query, "variables": login_payload}
                ).encode("utf-8")
                active_body_preview = json.dumps({"query": login_graphql_query[:120], "variables": redacted_vars})
            else:
                active_body_bytes = json.dumps(login_payload).encode("utf-8")
                active_body_preview = json.dumps(redacted_vars)

            def _build_form_login_bytes() -> bytes:
                form_data = dict(login_payload)
                with session._lock:
                    c_tok = session.csrf_token
                    c_field = session.csrf_field_name
                if c_tok and c_field and c_field not in form_data:
                    form_data[c_field] = c_tok
                return urlencode(form_data).encode("utf-8")

            receipt = self._send_wire(
                actor=alias,
                method="POST",
                url=login_url,
                path=login_path,
                query=login_query,
                headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                body_bytes=active_body_bytes,
                body_preview=active_body_preview,
                record_receipt=False,
            )
            if not login_graphql_query and receipt["status"] in {400, 415}:
                active_content_type = "application/x-www-form-urlencoded"
                active_body_bytes = _build_form_login_bytes()
                active_body_preview = "<REDACTED_FORM_LOGIN>"
                receipt = self._send_wire(
                    actor=alias,
                    method="POST",
                    url=login_url,
                    path=login_path,
                    query=login_query,
                    headers=session.build_headers("POST", {"Content-Type": active_content_type}),
                    body_bytes=active_body_bytes,
                    body_preview=active_body_preview,
                    record_receipt=False,
                )

            # Pre-login CSRF harvesting: if login POST returns 403 mentioning CSRF and session.csrf_token
            # is still empty, issue one bounded GET to login_path (falling back to "/" on 404/405)
            # to capture CSRF cookie/token via update_from_response, then retry POST once.
            with session._lock:
                has_csrf = bool(session.csrf_token)
            if receipt["status"] == 403 and not has_csrf and bool(receipt.get("_body_mentions_csrf")):
                candidate_paths = [self.actors.login_path]
                if self.actors.login_path != "/":
                    candidate_paths.append("/")
                harvested = False
                for c_path in candidate_paths:
                    try:
                        h_url, h_path, h_query = self.resolve_in_scope(c_path)
                    except ScopeViolationError:
                        continue
                    h_rec = self._send_wire(
                        actor=alias,
                        method="GET",
                        url=h_url,
                        path=h_path,
                        query=h_query,
                        headers=session.build_headers("GET"),
                        body_bytes=None,
                        body_preview="",
                        record_receipt=False,
                    )
                    if h_rec["status"] not in {404, 405}:
                        harvested = True
                        break
                if harvested:
                    retry_headers = session.build_headers("POST", {"Content-Type": active_content_type})
                    with session._lock:
                        if (
                            session.csrf_token
                            and session.csrf_header_name == "X-CSRFToken"
                            and not session.csrf_field_name
                        ):
                            retry_headers.setdefault("X-CSRF-Token", session.csrf_token)
                    if active_content_type == "application/x-www-form-urlencoded":
                        active_body_bytes = _build_form_login_bytes()
                    receipt = self._send_wire(
                        actor=alias,
                        method="POST",
                        url=login_url,
                        path=login_path,
                        query=login_query,
                        headers=retry_headers,
                        body_bytes=active_body_bytes,
                        body_preview=active_body_preview,
                        record_receipt=False,
                    )
                    if (
                        not login_graphql_query
                        and active_content_type == "application/json"
                        and receipt["status"] in {400, 415}
                    ):
                        active_content_type = "application/x-www-form-urlencoded"
                        active_body_bytes = _build_form_login_bytes()
                        active_body_preview = "<REDACTED_FORM_LOGIN>"
                        retry_form_headers = session.build_headers("POST", {"Content-Type": active_content_type})
                        with session._lock:
                            if (
                                session.csrf_token
                                and session.csrf_header_name == "X-CSRFToken"
                                and not session.csrf_field_name
                            ):
                                retry_form_headers.setdefault("X-CSRF-Token", session.csrf_token)
                        receipt = self._send_wire(
                            actor=alias,
                            method="POST",
                            url=login_url,
                            path=login_path,
                            query=login_query,
                            headers=retry_form_headers,
                            body_bytes=active_body_bytes,
                            body_preview=active_body_preview,
                            record_receipt=False,
                        )

            final_status = int(receipt["status"])
            final_error = str(receipt.get("error") or "")
            with session._lock:
                session.last_auth_status = final_status
                session.last_auth_path = login_path
                session.last_auth_error = final_error

            if 200 <= final_status < 400:
                if login_graphql_query and receipt.get("_graphql_has_errors"):
                    with session._lock:
                        has_session_mat = bool(session.cookies or session.access_token)
                        if not has_session_mat:
                            session.last_auth_error = "graphql_errors"
                            return False
                with session._lock:
                    session.authenticated = True
                    session.last_auth_error = ""
                return True
            return False

    def authenticate_all_actors(self) -> dict[str, bool]:
        """Eagerly authenticate all non-anon actors with login credentials not yet authenticated."""
        with self.actors._lock:
            candidates = list(self.actors.actors.items())
        results: dict[str, bool] = {}
        for alias, session in candidates:
            if alias == "anon":
                continue
            with session._lock:
                needs_login = bool(session.login_payload) and not session.authenticated
            if not needs_login:
                continue
            try:
                results[alias] = bool(self.authenticate_actor(alias, force_login=False))
            except (BudgetExhaustedError, ServiceDegradationError):
                raise
            except Exception:
                results[alias] = False
        return results

    def filter_login_fallback_candidates(
        self,
        candidate_paths: Sequence[str],
        *,
        max_candidates: int = _LOGIN_FALLBACK_MAX_CANDIDATES,
    ) -> list[str]:
        """Filter discovered routes to bounded, safe, in-scope login-like endpoints."""
        cap = max(0, min(int(max_candidates), 5))
        if cap == 0 or not candidate_paths:
            return []
        try:
            _, current_norm, _ = self.resolve_in_scope(self.actors.login_path, allow_websocket=False)
        except ScopeViolationError:
            current_norm = str(self.actors.login_path or "").strip()
        current_cmp = current_norm.rstrip("/") or "/"

        strong: list[str] = []
        weak: list[str] = []
        seen: set[str] = set()

        for raw in candidate_paths:
            raw_str = str(raw or "").strip()
            if not raw_str:
                continue
            try:
                _clean_url, norm_path, _ = self.resolve_in_scope(raw_str, allow_websocket=False)
            except ScopeViolationError:
                continue
            path_cmp = norm_path.rstrip("/") or "/"
            if path_cmp == current_cmp or path_cmp in seen:
                continue
            if "{" in norm_path or "}" in norm_path or "/:" in norm_path:
                continue
            path_low = norm_path.lower()
            if any(path_low.endswith(ext) for ext in _LOGIN_FALLBACK_SKIP_EXTENSIONS):
                continue
            if match_logout_route(norm_path) is not None:
                continue
            if _LOGIN_FALLBACK_EXCLUDE_RE.search(path_low):
                continue
            if _LOGIN_FALLBACK_STRONG_RE.search(path_low):
                seen.add(path_cmp)
                strong.append(norm_path)
            elif _LOGIN_FALLBACK_WEAK_RE.search(path_low):
                seen.add(path_cmp)
                weak.append(norm_path)

        return [*strong, *weak][:cap]

    def retry_unauthenticated_actors_with_discovered_login_paths(
        self,
        candidate_paths: Sequence[str],
        *,
        max_candidates: int = _LOGIN_FALLBACK_MAX_CANDIDATES,
    ) -> dict[str, bool]:
        """Retry credentialed actors whose initial login hit 404/405 against discovered login paths.

        Fail-closed: never activates when initial login returned 401/403 or other non-404/405
        responses (which indicate a valid endpoint), and caps probes to ``max_candidates`` safe
        in-scope routes.
        """
        eligible_aliases = self.actors.actors_failed_with_missing_login_route()
        if not eligible_aliases:
            return {}

        try:
            _, current_login_norm, _ = self.resolve_in_scope(self.actors.login_path, allow_websocket=False)
        except ScopeViolationError:
            current_login_norm = str(self.actors.login_path or "").strip()
        current_cmp = current_login_norm.rstrip("/") or "/"
        with self.actors._lock:
            all_sessions = list(self.actors.actors.items())
        for alias, sess in all_sessions:
            if alias == "anon":
                continue
            with sess._lock:
                if not sess.login_payload:
                    continue
                last_cmp = (sess.last_auth_path or "").rstrip("/") or "/"
                if (
                    sess.last_auth_status is not None
                    and last_cmp == current_cmp
                    and sess.last_auth_status not in _LOGIN_MISSING_ROUTE_STATUS_CODES
                ):
                    return {}

        filtered = self.filter_login_fallback_candidates(
            candidate_paths,
            max_candidates=max_candidates,
        )
        if not filtered:
            return {}

        original_login_path = self.actors.login_path
        probe_alias = eligible_aliases[0]
        winning_path: str | None = None
        results: dict[str, bool] = {}

        for cand_path in filtered:
            self.actors.login_path = cand_path
            try:
                ok = bool(self.authenticate_actor(probe_alias, force_login=False))
            except (BudgetExhaustedError, ServiceDegradationError):
                self.actors.login_path = original_login_path
                raise
            except Exception:
                ok = False
            if ok:
                winning_path = cand_path
                results[probe_alias] = True
                break

        if winning_path is None:
            self.actors.login_path = original_login_path
            return {alias: False for alias in eligible_aliases}

        for alias in eligible_aliases[1:]:
            try:
                results[alias] = bool(self.authenticate_actor(alias, force_login=False))
            except (BudgetExhaustedError, ServiceDegradationError):
                raise
            except Exception:
                results[alias] = False
        return results

    def _try_refresh_actor_session(self, alias: str) -> bool:
        """Renew an expired authenticated actor session via refresh_path or fallback re-login."""
        if not alias or alias == "anon":
            return False
        session = self.actors.get(alias)
        with self._lock:
            if self._in_session_refresh:
                return False
            self._in_session_refresh = True
        try:
            with self._auth_lock:
                with session._lock:
                    was_authenticated = bool(session.authenticated)
                    refresh_tok = session.refresh_token
                    actor_refresh_path = session.refresh_path
                    has_password = bool(session.password)
                if not was_authenticated:
                    return False

                attempted_step1_refresh = False
                if refresh_tok and actor_refresh_path:
                    attempted_step1_refresh = True
                    try:
                        r_url, r_path, r_query = self.resolve_in_scope(
                            actor_refresh_path,
                            allow_websocket=False,
                        )
                        r_body = json.dumps({"refresh_token": refresh_tok}).encode("utf-8")
                        r_headers = session.build_headers("POST", {"Content-Type": "application/json"})
                        r_receipt = self._send_wire(
                            actor=alias,
                            method="POST",
                            url=r_url,
                            path=r_path,
                            query=r_query,
                            headers=r_headers,
                            body_bytes=r_body,
                            body_preview='{"refresh_token":"<REDACTED>"}',
                            record_receipt=False,
                        )
                        if 200 <= int(r_receipt["status"]) < 300:
                            with session._lock:
                                session.last_auth_status = int(r_receipt["status"])
                                session.last_auth_path = r_path
                                session.last_auth_error = ""
                                session.authenticated = True
                            return True
                    except (BudgetExhaustedError, ServiceDegradationError):
                        raise
                    except Exception:
                        pass

                if has_password and self.actors.login_path:
                    prev_skip = self._refresh_already_attempted
                    self._refresh_already_attempted = attempted_step1_refresh
                    try:
                        return bool(self.authenticate_actor(alias, force_login=True))
                    finally:
                        self._refresh_already_attempted = prev_skip
                return False
        finally:
            with self._lock:
                self._in_session_refresh = False

    def _auth_exempt_paths(self, actor_refresh_path: str = "") -> set[str]:
        """Return normalized paths (login / refresh) that must never trigger mid-run auto-refresh."""
        exempt: set[str] = set()
        for raw_p in (self.actors.login_path, self.actors.refresh_path, actor_refresh_path):
            clean = str(raw_p or "").strip()
            if not clean:
                continue
            try:
                _, norm_p, _ = self.resolve_in_scope(clean, allow_websocket=False)
                exempt.add(norm_p.rstrip("/") or "/")
            except ScopeViolationError:
                parsed_p = urlsplit(clean).path or "/"
                exempt.add(parsed_p.rstrip("/") or "/")
        return exempt

    @staticmethod
    def _prepare_request_body(
        *,
        norm_method: str,
        session: ActorSession,
        extra_headers: dict[str, str],
        has_auth_override: bool,
        has_files: bool,
        files: Sequence[dict[str, Any]] | None,
        json_body: Any,
        form_body: dict[str, Any] | None,
        raw_body: str | None,
    ) -> tuple[bytes | None, str, dict[str, str]]:
        """Encode request body without mutating caller dicts, injecting CSRF form fields when appropriate."""
        eff_headers = dict(extra_headers)
        with session._lock:
            csrf_tok = session.csrf_token
            csrf_field = session.csrf_field_name
            base_ct = next(
                (v for k, v in session.base_headers.items() if k.lower() == "content-type"),
                "",
            )
        should_inject_csrf = (
            norm_method in _MUTATING_METHODS
            and bool(csrf_tok and csrf_field)
            and not has_auth_override
        )

        body_bytes: bytes | None = None
        body_preview = ""
        if has_files:
            assert files is not None
            if json_body is not None or raw_body is not None:
                raise ValueError("files cannot be combined with json_body or raw_body")
            eff_form_fields: Any = form_body
            if should_inject_csrf:
                if form_body is None:
                    eff_form_fields = {csrf_field: csrf_tok}
                elif isinstance(form_body, dict):
                    eff_form_fields = dict(form_body)
                    if not any(str(k) == csrf_field for k in eff_form_fields):
                        eff_form_fields[csrf_field] = csrf_tok
            body_bytes, multipart_ct, body_preview = _encode_multipart_form_data(
                files,
                form_fields=eff_form_fields,
            )
            if not any(k.lower() == "content-type" for k in eff_headers):
                eff_headers["Content-Type"] = multipart_ct
        elif json_body is not None:
            body_preview = json.dumps(json_body, ensure_ascii=False)
            body_bytes = body_preview.encode("utf-8")
            if not any(k.lower() == "content-type" for k in eff_headers):
                eff_headers["Content-Type"] = "application/json"
        elif form_body is not None:
            eff_form = {str(k): str(v) for k, v in form_body.items()}
            if should_inject_csrf and csrf_field not in eff_form:
                eff_form[csrf_field] = csrf_tok
            body_preview = urlencode(eff_form)
            body_bytes = body_preview.encode("utf-8")
            if not any(k.lower() == "content-type" for k in eff_headers):
                eff_headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw_body is not None:
            body_preview = str(raw_body)
            explicit_ct = next(
                (v for k, v in eff_headers.items() if k.lower() == "content-type"),
                base_ct,
            )
            media_type = str(explicit_ct or "").split(";", 1)[0].strip().lower()
            if should_inject_csrf and media_type == "application/x-www-form-urlencoded":
                existing_keys = {k for k, _ in parse_qsl(body_preview, keep_blank_values=True)}
                if csrf_field not in existing_keys:
                    csrf_pair = urlencode([(csrf_field, csrf_tok)])
                    if not body_preview:
                        body_preview = csrf_pair
                    elif body_preview.endswith("&"):
                        body_preview = f"{body_preview}{csrf_pair}"
                    else:
                        body_preview = f"{body_preview}&{csrf_pair}"
            body_bytes = body_preview.encode("utf-8")

        return body_bytes, body_preview, eff_headers

    def _refresh_csrf_from_session(self, alias: str) -> None:
        session = self.actors.get(alias)
        if alias == "anon" or not self.actors.session_check_path:
            return
        with self._auth_lock:
            try:
                c_url, c_path, c_query = self.resolve_in_scope(self.actors.session_check_path)
                headers = session.build_headers("GET")
                self._send_wire(
                    actor=alias,
                    method="GET",
                    url=c_url,
                    path=c_path,
                    query=c_query,
                    headers=headers,
                    body_bytes=None,
                    body_preview="",
                    record_receipt=False,
                )
            except (BudgetExhaustedError, ServiceDegradationError):
                raise
            except Exception:
                pass

    @staticmethod
    def _merge_hop_cookies(headers: dict[str, str], hop_cookies: dict[str, str]) -> dict[str, str]:
        """Overlay cookies received during earlier redirect hops onto a request header dict."""
        if not hop_cookies:
            return headers
        merged_headers = dict(headers)
        existing_cookie_key = next((k for k in merged_headers if k.lower() == "cookie"), None)
        cookie_map: dict[str, str] = {}
        if existing_cookie_key is not None:
            for part in str(merged_headers[existing_cookie_key]).split(";"):
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    if ck.strip():
                        cookie_map[ck.strip()] = cv.strip()
        cookie_map.update(hop_cookies)
        if existing_cookie_key is not None and existing_cookie_key != "Cookie":
            merged_headers.pop(existing_cookie_key, None)
        merged_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in sorted(cookie_map.items()))
        return merged_headers

    def request(
        self,
        *,
        method: str = "GET",
        url: str,
        actor: str = "anon",
        headers: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        json_body: Any = None,
        form_body: dict[str, Any] | None = None,
        raw_body: str | None = None,
        files: Sequence[dict[str, Any]] | None = None,
        force: bool = False,
        save_session_as: str = "",
        auth_header_name: str = "",
        follow_redirects: bool = False,
        allow_lifecycle_routes: bool | None = None,
    ) -> dict[str, Any]:
        """Execute a scope-locked, metered, receipted HTTP or WebSocket request."""
        clean_auth_header_name = _validate_auth_header_name(auth_header_name, strict=True)
        raw_url_str = str(url or "").strip()
        norm_method = str(method or "GET").strip().upper()
        is_ws = raw_url_str.lower().startswith(("ws://", "wss://")) or norm_method == "WS"
        if is_ws:
            if norm_method not in self.allowed_methods and not (norm_method == "WS" and "GET" in self.allowed_methods):
                raise MethodNotAllowedError(
                    f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.allowed_methods)}"
                )
        elif norm_method not in self.allowed_methods:
            raise MethodNotAllowedError(
                f"HTTP method {norm_method!r} not allowed; permitted: {sorted(self.allowed_methods)}"
            )
        eff_allow_lifecycle = (
            self.allow_lifecycle_routes
            if allow_lifecycle_routes is None
            else bool(allow_lifecycle_routes)
        )
        clean_url, path, norm_query = self._merge_query(
            url,
            query,
            allow_websocket=is_ws,
            allow_lifecycle_routes=eff_allow_lifecycle,
        )
        if is_ws and clean_url.lower().startswith(("http://", "https://")):
            ws_scheme = "wss://" if clean_url.lower().startswith("https://") else "ws://"
            clean_url = ws_scheme + clean_url.split("://", 1)[1]
        session = self.actors.get(actor)

        extra_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        self._check_actor_logout_guard(
            path=path,
            actor=actor,
            session=session,
            extra_headers=extra_headers,
            allow_lifecycle_routes=eff_allow_lifecycle,
        )
        auth_override_keys = set(_AUTH_OVERRIDE_HEADERS)
        with session._lock:
            actor_auth_hdr = session.auth_header_name.strip().lower()
            is_session_auth = bool(session.authenticated)
        if actor_auth_hdr:
            auth_override_keys.add(actor_auth_hdr)
        has_auth_override = any(k.strip().lower() in auth_override_keys for k in extra_headers)
        if actor != "anon" and not has_auth_override and not is_session_auth:
            self.authenticate_actor(actor, force_login=False)

        if is_ws:
            ws_messages: list[str] | None = None
            ws_preview = ""
            if json_body is not None:
                ws_preview = json.dumps(json_body, ensure_ascii=False)
                ws_messages = [ws_preview]
            elif raw_body is not None:
                ws_preview = str(raw_body)
                ws_messages = [ws_preview]
            ws_headers = session.build_headers("GET", extra_headers)
            ws_receipt = self._send_websocket_wire(
                actor=actor,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=ws_headers,
                send_messages=ws_messages,
                body_preview=ws_preview,
            )
            ws_result = dict(ws_receipt)
            ws_result["cached"] = False
            return ws_result

        has_files = False
        if files is not None:
            if isinstance(files, (str, bytes, bytearray, dict)) or not isinstance(files, Sequence):
                raise ValueError("files must be a list of file objects")
            has_files = len(files) > 0

        body_bytes, body_preview, eff_extra_headers = self._prepare_request_body(
            norm_method=norm_method,
            session=session,
            extra_headers=extra_headers,
            has_auth_override=has_auth_override,
            has_files=has_files,
            files=files,
            json_body=json_body,
            form_body=form_body,
            raw_body=raw_body,
        )

        cache_key = (
            actor,
            norm_method,
            _canonical_url(clean_url),
            tuple(sorted((k.lower(), v) for k, v in eff_extra_headers.items())),
            bool(follow_redirects),
        )
        if norm_method in {"GET", "HEAD"} and not force and not save_session_as:
            with self._lock:
                cached = self._cache.get(cache_key)
                if cached is not None:
                    result = dict(cached)
                    result["cached"] = True
                    return result

        req_headers = session.build_headers(norm_method, eff_extra_headers)
        hop_cookies: dict[str, str] = {}
        receipt = self._send_wire_with_rate_limit_retry(
            actor=actor,
            method=norm_method,
            url=clean_url,
            path=path,
            query=norm_query,
            headers=req_headers,
            body_bytes=body_bytes,
            body_preview=body_preview,
            save_session_as=save_session_as,
            auth_header_name=clean_auth_header_name,
            out_cookies=hop_cookies if follow_redirects else None,
        )

        # Auto mid-run session refresh / re-login once on unexpected 401 when not overriding auth.
        with session._lock:
            actor_refresh_path = session.refresh_path
        auth_exempt_paths = self._auth_exempt_paths(actor_refresh_path)
        norm_req_path = path.rstrip("/") or "/"
        if (
            receipt["status"] == 401
            and actor != "anon"
            and not has_auth_override
            and not save_session_as
            and norm_req_path not in auth_exempt_paths
        ):
            if self._try_refresh_actor_session(actor):
                body_bytes, body_preview, eff_extra_headers = self._prepare_request_body(
                    norm_method=norm_method,
                    session=session,
                    extra_headers=extra_headers,
                    has_auth_override=has_auth_override,
                    has_files=has_files,
                    files=files,
                    json_body=json_body,
                    form_body=form_body,
                    raw_body=raw_body,
                )
                req_headers = session.build_headers(norm_method, eff_extra_headers)
                hop_cookies.clear()
                receipt = self._send_wire_with_rate_limit_retry(
                    actor=actor,
                    method=norm_method,
                    url=clean_url,
                    path=path,
                    query=norm_query,
                    headers=req_headers,
                    body_bytes=body_bytes,
                    body_preview=body_preview,
                    out_cookies=hop_cookies if follow_redirects else None,
                )

        # Auto CSRF refresh once on mutating 403 mentioning CSRF when caller didn't override a CSRF header.
        has_csrf_override = any(k.lower() in _CSRF_HEADER_NAMES for k in extra_headers)
        if (
            receipt["status"] == 403
            and norm_method in _MUTATING_METHODS
            and actor != "anon"
            and not has_csrf_override
            and "csrf" in (receipt.get("body") or "").lower()
        ):
            self._refresh_csrf_from_session(actor)
            body_bytes, body_preview, eff_extra_headers = self._prepare_request_body(
                norm_method=norm_method,
                session=session,
                extra_headers=extra_headers,
                has_auth_override=has_auth_override,
                has_files=has_files,
                files=files,
                json_body=json_body,
                form_body=form_body,
                raw_body=raw_body,
            )
            req_headers = session.build_headers(norm_method, eff_extra_headers)
            hop_cookies.clear()
            receipt = self._send_wire_with_rate_limit_retry(
                actor=actor,
                method=norm_method,
                url=clean_url,
                path=path,
                query=norm_query,
                headers=req_headers,
                body_bytes=body_bytes,
                body_preview=body_preview,
                out_cookies=hop_cookies if follow_redirects else None,
            )

        redirect_chain: list[dict[str, Any]] = []
        if follow_redirects:
            cur_method = norm_method
            cur_url = clean_url
            cur_body_bytes = body_bytes
            cur_body_preview = body_preview
            cur_extra_headers = dict(eff_extra_headers)
            for _ in range(_MAX_REDIRECTS):
                status_code = int(receipt["status"])
                location = str(receipt.get("redirect_location") or "").strip()
                if status_code not in _REDIRECT_STATUS_CODES or not location:
                    break
                if location.startswith("//"):
                    raise ScopeViolationError(f"scheme-relative redirect blocked: {location!r}")
                joined_target = urljoin(cur_url, location)
                next_url, next_path, next_query = self.resolve_in_scope(
                    joined_target,
                    allow_websocket=False,
                    allow_lifecycle_routes=eff_allow_lifecycle,
                )
                self._check_actor_logout_guard(
                    path=next_path,
                    actor=actor,
                    session=session,
                    extra_headers=cur_extra_headers,
                    allow_lifecycle_routes=eff_allow_lifecycle,
                )
                redirect_chain.append({
                    "receipt_id": str(receipt.get("receipt_id") or ""),
                    "method": cur_method,
                    "url": cur_url,
                    "status": status_code,
                    "location": location,
                })
                if status_code == 303 and cur_method != "HEAD":
                    cur_method = "GET"
                    cur_body_bytes = None
                    cur_body_preview = ""
                    cur_extra_headers = {
                        k: v for k, v in cur_extra_headers.items()
                        if k.lower() not in {"content-type", "content-length"}
                    }
                elif status_code in {301, 302} and cur_method == "POST":
                    cur_method = "GET"
                    cur_body_bytes = None
                    cur_body_preview = ""
                    cur_extra_headers = {
                        k: v for k, v in cur_extra_headers.items()
                        if k.lower() not in {"content-type", "content-length"}
                    }
                # 307/308 preserve method and request body intact.
                if cur_method not in self.allowed_methods:
                    raise MethodNotAllowedError(
                        f"Redirect follow-up method {cur_method!r} not allowed; "
                        f"permitted: {sorted(self.allowed_methods)}"
                    )
                cur_url = next_url
                hop_headers = session.build_headers(cur_method, cur_extra_headers)
                if hop_cookies:
                    hop_headers = self._merge_hop_cookies(hop_headers, hop_cookies)
                new_hop_cookies: dict[str, str] = {}
                receipt = self._send_wire_with_rate_limit_retry(
                    actor=actor,
                    method=cur_method,
                    url=next_url,
                    path=next_path,
                    query=next_query,
                    headers=hop_headers,
                    body_bytes=cur_body_bytes,
                    body_preview=cur_body_preview,
                    save_session_as=save_session_as,
                    auth_header_name=clean_auth_header_name,
                    out_cookies=new_hop_cookies,
                )
                if new_hop_cookies:
                    hop_cookies.update(new_hop_cookies)

        if (
            str(actor or "anon").strip() == "anon"
            and 200 <= int(receipt.get("status") or 0) < 300
            and extra_headers
        ):
            for hk, hv in extra_headers.items():
                hk_clean = hk.strip()
                hv_clean = str(hv or "").strip()
                if (
                    hk_clean.lower() in _ANON_OBSERVED_AUTH_HEADERS
                    and hv_clean
                    and not hv_clean.startswith("<REDACTED")
                ):
                    self.actors.register_discovered_auth_header(hk_clean)
                    break

        result = dict(receipt)
        if redirect_chain:
            result["redirect_chain"] = redirect_chain

        if norm_method in _MUTATING_METHODS and 200 <= receipt["status"] < 400:
            with self._lock:
                self._cache.clear()
        elif norm_method in {"GET", "HEAD"} and 200 <= receipt["status"] < 500 and receipt["status"] != 429:
            with self._lock:
                self._cache[cache_key] = dict(result)

        result["cached"] = False
        return result
