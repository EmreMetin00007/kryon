"""HAR multi-step workflow extractor, secret redactor, mutation planner, and replay helper.

Purely offline HAR 1.2 parsing (zero Playwright/network side effects during extraction)
with strict ScopeGuard origin/exclusion filtering, credential stripping, cross-step ID
chaining, business-logic/race mutation planning, and AgenticHTTPClient replay support.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime
import errno
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from agentic_http import STATIC_EXTENSIONS, is_static_asset_url  # noqa: E402
from agentic_surface import is_id_segment  # noqa: E402
from target_bootstrap import ScopeGuard, normalize_path  # noqa: E402

HAR_FLOW_SCHEMA = "har-flow/1"
MAX_HAR_BYTES = 20 * 1024 * 1024  # 20 MiB hard cap
MAX_HAR_FLOWS = 10
MAX_STEPS_PER_FLOW = 12
_MAX_RESPONSE_JSON_BYTES = 512 * 1024
_MAX_HEADER_COUNT = 16
_MAX_HEADER_VALUE_CHARS = 256
_MAX_TEMPLATE_DEPTH = 6
_MAX_TEMPLATE_KEYS = 32
_MAX_TEMPLATE_LIST = 6
_MAX_TEMPLATE_STR_LEN = 128

_ALLOWED_FLOW_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_HAR_STATIC_EXTENSIONS: frozenset[str] = STATIC_EXTENSIONS | frozenset({
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".tsx",
    ".ts",
    ".scss",
    ".less",
    ".otf",
    ".avif",
    ".bmp",
    ".mp4",
    ".mp3",
    ".webm",
    ".ogg",
    ".wav",
    ".wasm",
})

_STATIC_RESPONSE_MIME_PREFIXES = ("image/", "font/", "video/", "audio/")
_STATIC_RESPONSE_MIMES = frozenset({
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "application/wasm",
})

_STRIPPED_EXACT_HEADERS = frozenset({
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
    # Hop-by-hop / transport / browser boilerplate
    "host",
    "content-length",
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
    "accept-encoding",
    "accept-language",
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

_STRIPPED_HEADER_PREFIXES = ("sec-", "x-b3-", "x-amz-", ":")
_SECRET_HEADER_TOKENS = frozenset({
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
    "key",
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
})
_SECRET_HEADER_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "apikey",
    "api_key",
    "csrf",
    "xsrf",
    "session",
    "auth",
    "private_key",
    "signature",
    "credential",
    "jwt",
    "bearer",
    "hmac",
)

_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_JWT_LIKE_RE = re.compile(r"(?:^|(?<![A-Za-z0-9_-]))eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*(?:$|(?![A-Za-z0-9_-]))")
_EMAIL_VALUE_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,128}\.[A-Za-z]{2,24}$")
_AWS_KEY_VALUE_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_KNOWN_SECRET_TOKEN_RE = re.compile(
    r"\b(?:(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}"
    r"|github_pat_[A-Za-z0-9_]{12,}"
    r"|sk_(?:live|test)_[0-9A-Za-z]{8,}"
    r"|xox[baprs]-[0-9A-Za-z-]{8,}"
    r"|AIza[0-9A-Za-z_-]{16,})\b"
)
_PEM_MARKER_RE = re.compile(r"-----BEGIN\s+[A-Z0-9 ]+-----")
_COOKIE_PAIR_VALUE_RE = re.compile(
    r"(?:^|;\s*)[A-Za-z0-9_.-]{1,48}=[^;\s]{1,256}\s*;\s*"
    r"(?:[A-Za-z0-9_.-]{1,48}=[^;\s]{1,256}|(?:httponly|secure|samesite|path|domain|max-age|expires)\b)",
    re.IGNORECASE,
)

_SENSITIVE_JSON_SUBSTRINGS = (
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
_SENSITIVE_JSON_TOKENS = frozenset({
    "pwd",
    "auth",
    "authorization",
    "csrf",
    "xsrf",
    "session",
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

_NUMERIC_LOGIC_TOKENS = frozenset({
    "price",
    "unit_price",
    "total",
    "subtotal",
    "amount",
    "quantity",
    "qty",
    "count",
    "discount",
    "discount_rate",
    "points",
    "point",
    "puan",
    "balance",
    "credit",
    "credits",
    "wallet",
    "limit",
    "fee",
    "rate",
    "percent",
    "tax",
    "shipping_fee",
})
_ROLE_STATUS_TOKENS = frozenset({
    "role",
    "roles",
    "is_admin",
    "admin",
    "is_staff",
    "is_superuser",
    "permission",
    "permissions",
    "scope",
    "scopes",
    "status",
    "state",
    "stage",
    "tier",
    "plan",
    "level",
    "verified",
    "approved",
    "paid",
})
_OWNER_BOLA_TOKENS = frozenset({
    "user_id",
    "owner_id",
    "account_id",
    "tenant_id",
    "org_id",
    "company_id",
    "customer_id",
    "member_id",
    "profile_id",
    "order_id",
    "cart_id",
    "basket_id",
    "wallet_id",
    "address_id",
    "invoice_id",
})
_RACE_PATH_TOKENS: tuple[tuple[str, str], ...] = (
    ("puan-aktar", "puan-aktar"),
    ("puan_aktar", "puan-aktar"),
    ("coupon", "coupon"),
    ("coupons", "coupon"),
    ("kupon", "coupon"),
    ("redeem", "redeem"),
    ("checkout", "checkout"),
    ("odeme", "checkout"),
    ("transfer", "transfer"),
    ("voucher", "voucher"),
    ("vouchers", "voucher"),
    ("claim", "claim"),
    ("promo", "promo"),
    ("withdraw", "withdraw"),
    ("refund", "refund"),
    ("iade", "refund"),
    ("payment", "payment"),
    ("payments", "payment"),
    ("pay", "pay"),
    ("vote", "vote"),
    ("bonus", "bonus"),
    ("reward", "reward"),
    ("gift", "gift"),
    ("checkin", "checkin"),
    ("check-in", "checkin"),
)
_TERMINAL_PATH_TOKENS = frozenset({"checkout", "odeme", "payment", "pay", "confirm", "complete", "logout", "signout"})

_PRODUCED_ID_EXACT_TOKENS = frozenset({
    "id",
    "uuid",
    "uid",
    "guid",
    "reference",
    "ref",
    "slug",
    "order_id",
    "cart_id",
    "basket_id",
    "item_id",
    "coupon_id",
    "payment_id",
    "invoice_id",
    "ticket_id",
    "user_id",
    "account_id",
    "tenant_id",
    "address_id",
    "product_id",
    "transaction_id",
})
_IGNORED_ID_SCALARS = frozenset({"true", "false", "null", "none", "ok", "pending", "active", "paid", "failed"})
_CAMEL_ID_KEY_RE = re.compile(r"^[a-z][A-Za-z0-9]*Id$")
_API_STEP_PATH_RE = re.compile(r"^/(?:api|ajax[-_]?api|bff|rest|rpc|graphql|v\d+(?:\.\d+)?)(?:/|$)", re.I)
_XML_CDATA_RE = re.compile(r"<!\[CDATA\[.*?\]\]>", re.DOTALL)
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_XML_OPEN_TAG_RE = re.compile(r"<([A-Za-z_][A-Za-z0-9_.:-]{0,63})(?=[\s/>])")
_NUMERIC_STR_RE = re.compile(r"^-?\d+(?:\.\d+)?$")
_XML_CONTENT_TYPES = frozenset({"application/xml", "text/xml", "application/soap+xml"})
_MAX_XML_TAGS = 24


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ch == "\x7f" for ch in value)


def _to_snake_tokens(name: str) -> tuple[str, list[str]]:
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", str(name or "")).strip().lower().replace("-", "_")
    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(snake) if tok]
    return snake, tokens


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _read_regular_har_text(path: Path | str, *, max_bytes: int | None = None) -> str:
    """Safely read a regular UTF-8 HAR file, rejecting symlinks, special files, and oversized files."""
    cap_bytes = MAX_HAR_BYTES if max_bytes is None else int(max_bytes)
    if isinstance(path, str) and not path.strip():
        raise ValueError("HAR file path is required")
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError:
        raise ValueError(f"HAR file is missing or unreadable: {raw_path}") from None
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"HAR file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"HAR file must be a regular file: {raw_path}")
    if st.st_size > cap_bytes:
        raise ValueError(
            f"HAR file exceeds maximum allowed size ({cap_bytes} bytes): {raw_path}"
        )

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"HAR file must not be a symlink: {raw_path}") from None
        raise ValueError(f"failed to read HAR file: {raw_path}") from None

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            os.close(fd)
            raise ValueError(f"HAR file must be a regular file: {raw_path}")
        if fd_stat.st_size > cap_bytes:
            os.close(fd)
            raise ValueError(
                f"HAR file exceeds maximum allowed size ({cap_bytes} bytes): {raw_path}"
            )
    except ValueError:
        raise
    except OSError:
        try:
            os.close(fd)
        except OSError:
            pass
        raise ValueError(f"failed to read HAR file: {raw_path}") from None

    try:
        with os.fdopen(fd, "rb") as handle:
            raw_bytes = handle.read(cap_bytes + 1)
    except OSError:
        raise ValueError(f"failed to read HAR file: {raw_path}") from None

    if len(raw_bytes) > cap_bytes:
        raise ValueError(
            f"HAR file exceeds maximum allowed size ({cap_bytes} bytes): {raw_path}"
        )
    try:
        return raw_bytes.decode("utf-8").lstrip("\ufeff")
    except UnicodeDecodeError:
        raise ValueError(f"HAR file is not valid UTF-8: {raw_path}") from None


def _validate_har_dict(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("HAR payload must be a JSON object")
    log = data.get("log")
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise ValueError("HAR payload must contain a 'log.entries' array")
    return data


def _load_har_source(source: Path | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return _validate_har_dict(source)
    if isinstance(source, (Path, str)):
        raw_text = _read_regular_har_text(source)
        parsed: Any = None
        parse_failed = False
        try:
            parsed = json.loads(raw_text)
        except ValueError:
            parse_failed = True
        if parse_failed:
            raise ValueError("HAR file is not valid JSON")
        return _validate_har_dict(parsed)
    raise ValueError("HAR source must be a file path or dict")


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


def _has_secret_value_pattern(stripped: str) -> bool:
    low = stripped.lower()
    if "<redacted" in low:
        return True
    if low.startswith(("bearer ", "basic ", "token ", "digest ")) and len(stripped) > 8:
        return True
    if "aws4-hmac-sha256" in low:
        return True
    if _JWT_LIKE_RE.search(stripped):
        return True
    if _AWS_KEY_VALUE_RE.search(stripped) or _KNOWN_SECRET_TOKEN_RE.search(stripped):
        return True
    if _PEM_MARKER_RE.search(stripped):
        return True
    if _COOKIE_PAIR_VALUE_RE.search(stripped):
        return True
    return False


def _is_secret_header_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped or _has_control_chars(stripped):
        return True
    return _has_secret_value_pattern(stripped)


def _sanitize_app_headers(raw_headers: Any) -> dict[str, str]:
    """Extract fixed non-auth, non-hop-by-hop application headers from HAR headers."""
    pairs: list[tuple[str, str]] = []
    if isinstance(raw_headers, list):
        for item in raw_headers:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            if isinstance(name, str) and isinstance(value, str):
                pairs.append((name.strip(), value.strip()))
    elif isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if isinstance(k, str) and v is not None:
                pairs.append((k.strip(), str(v).strip()))

    cleaned: dict[str, str] = {}
    for name, value in pairs:
        if not name or _has_control_chars(name) or len(name) > 128:
            continue
        if _is_secret_header_name(name) or _is_secret_header_value(value):
            continue
        norm_val = value[:_MAX_HEADER_VALUE_CHARS]
        if name.lower() == "content-type":
            media = norm_val.split(";", 1)[0].strip().lower()
            if not media:
                continue
            norm_val = media
        for existing in [k for k in cleaned if k.lower() == name.lower() and k != name]:
            cleaned.pop(existing, None)
        cleaned[name] = norm_val
        if len(cleaned) >= _MAX_HEADER_COUNT:
            break
    return cleaned


def _is_sensitive_json_key(key: str) -> bool:
    snake, tokens = _to_snake_tokens(key)
    if not snake:
        return False
    if any(sub in snake for sub in _SENSITIVE_JSON_SUBSTRINGS):
        return True
    return snake in _SENSITIVE_JSON_TOKENS or any(tok in _SENSITIVE_JSON_TOKENS for tok in tokens)


def _is_sensitive_json_string(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if _has_secret_value_pattern(stripped):
        return True
    if _EMAIL_VALUE_RE.fullmatch(stripped):
        return True
    return False


def _sanitize_json_value(obj: Any, *, depth: int = 0) -> Any:
    """Recursively redact secret/PII fields while preserving schema, numeric values, and types."""
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
        if _is_sensitive_json_string(obj):
            return "<redacted>"
        if len(obj) > _MAX_TEMPLATE_STR_LEN:
            return obj[: _MAX_TEMPLATE_STR_LEN - 3] + "..."
        return obj
    if isinstance(obj, bool) or obj is None or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else 0.0
    return str(obj)[:_MAX_TEMPLATE_STR_LEN]


def _decode_har_text_payload(container: dict[str, Any], *, max_bytes: int = _MAX_RESPONSE_JSON_BYTES) -> str:
    raw_text = container.get("text")
    if not isinstance(raw_text, str) or not raw_text:
        return ""
    encoding = str(container.get("encoding") or "").strip().lower()
    if encoding == "base64":
        try:
            decoded = base64.b64decode(raw_text.encode("ascii"), validate=False)
            return decoded[:max_bytes].decode("utf-8", errors="replace")
        except Exception:
            return ""
    return raw_text[:max_bytes]


def _parse_json_payload(text: str) -> Any:
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _sanitize_form_template(raw_map: dict[str, Any]) -> dict[str, str]:
    """Redact sensitive keys/values in a form-urlencoded template and bound key/value sizes."""
    out: dict[str, str] = {}
    for k, v in list(raw_map.items())[:_MAX_TEMPLATE_KEYS]:
        key_s = str(k or "").strip()[:64]
        if not key_s or _has_control_chars(key_s):
            continue
        val_s = "" if v is None else str(v).strip()
        if (
            _is_sensitive_json_key(key_s)
            or _is_sensitive_json_string(val_s)
            or _has_control_chars(val_s)
        ):
            out[key_s] = "<redacted>"
        elif len(val_s) > _MAX_TEMPLATE_STR_LEN:
            out[key_s] = val_s[: _MAX_TEMPLATE_STR_LEN - 3] + "..."
        else:
            out[key_s] = val_s
    return out


def _parse_form_payload(
    post_data: dict[str, Any],
    req_text: str,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Parse HAR `application/x-www-form-urlencoded` body from `postData.params` or `req_text`."""
    raw_pairs: list[tuple[str, str]] = []
    raw_params = post_data.get("params")
    if isinstance(raw_params, list):
        for item in raw_params:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            if not isinstance(name, str):
                continue
            clean_k = name.strip()[:64]
            if not clean_k or _has_control_chars(clean_k):
                continue
            raw_v = item.get("value")
            val_s = str(raw_v).strip() if raw_v is not None else ""
            raw_pairs.append((clean_k, val_s))
    if not raw_pairs and req_text:
        for qk, qv in parse_qsl(req_text, keep_blank_values=True, max_num_fields=128):
            clean_k = qk.strip()[:64]
            if not clean_k or _has_control_chars(clean_k):
                continue
            raw_pairs.append((clean_k, qv.strip()))
    if not raw_pairs:
        return [], {}
    template_map: dict[str, Any] = {}
    for k, v in raw_pairs:
        if k not in template_map and len(template_map) < _MAX_TEMPLATE_KEYS:
            template_map[k] = v
    return raw_pairs, _sanitize_form_template(template_map)


def _extract_xml_tags(req_text: str, *, max_tags: int = _MAX_XML_TAGS) -> list[str]:
    """Extract unique top XML element names safely via regex (XXE-proof, zero text/value leakage)."""
    if not req_text:
        return []
    sample = req_text[:65536]
    cleaned = _XML_CDATA_RE.sub("", sample)
    cleaned = _XML_COMMENT_RE.sub("", cleaned)
    tags: list[str] = []
    seen: set[str] = set()
    for match in _XML_OPEN_TAG_RE.finditer(cleaned):
        tag = match.group(1).strip()[:64]
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
            if len(tags) >= max_tags:
                break
    return tags


def _header_value_ci(headers: dict[str, str], target: str) -> str:
    low = target.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return ""


def _is_candidate_id_key(key: str) -> bool:
    if _is_sensitive_json_key(key):
        return False
    snake, _ = _to_snake_tokens(key)
    if not snake:
        return False
    if snake in _PRODUCED_ID_EXACT_TOKENS:
        return True
    if snake.endswith(("_id", "_uuid", "_guid")):
        return True
    if _CAMEL_ID_KEY_RE.fullmatch(key.strip()):
        return True
    return False


def _extract_response_id_candidates(resp_json: Any) -> list[tuple[str, str, bool]]:
    """Extract `(field_name, value_str, require_key_or_path_match)` pairs from JSON response."""
    found: list[tuple[str, str, bool]] = []
    seen: set[tuple[str, str]] = set()

    def _walk(node: Any, depth: int) -> None:
        if depth > 4 or len(found) >= 32:
            return
        if isinstance(node, dict):
            for k, v in list(node.items())[:32]:
                k_str = str(k).strip()
                if not k_str:
                    continue
                if _is_candidate_id_key(k_str):
                    if isinstance(v, int) and not isinstance(v, bool) and v > 0:
                        val_s = str(v)
                        if (k_str, val_s) not in seen:
                            seen.add((k_str, val_s))
                            found.append((k_str, val_s, v < 10))
                    elif isinstance(v, str):
                        val_s = v.strip()
                        if (
                            1 <= len(val_s) <= 128
                            and not _has_control_chars(val_s)
                            and val_s.lower() not in _IGNORED_ID_SCALARS
                            and not _is_sensitive_json_string(val_s)
                            and (k_str, val_s) not in seen
                        ):
                            seen.add((k_str, val_s))
                            found.append((k_str, val_s, len(val_s) < 3))
                if isinstance(v, (dict, list)):
                    _walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:4]:
                if isinstance(item, (dict, list)):
                    _walk(item, depth + 1)

    _walk(resp_json, 0)
    return found


def _collect_request_scalars(
    path_segments: Sequence[str],
    query_pairs: Sequence[tuple[str, str]],
    req_json: Any,
) -> tuple[set[str], list[tuple[str, str]]]:
    """Collect path segments and `(key, value_str)` pairs from a request for ID chaining."""
    path_set = {seg for seg in path_segments if seg}
    kv_pairs: list[tuple[str, str]] = []
    for qk, qv in query_pairs:
        if qv and not _has_control_chars(qv):
            kv_pairs.append((qk, qv.strip()))

    def _walk(node: Any, depth: int) -> None:
        if depth > 5 or len(kv_pairs) >= 64:
            return
        if isinstance(node, dict):
            for k, v in list(node.items())[:32]:
                k_str = str(k).strip()
                if isinstance(v, int) and not isinstance(v, bool):
                    kv_pairs.append((k_str, str(v)))
                elif isinstance(v, str):
                    val_s = v.strip()
                    if val_s and len(val_s) <= 128:
                        kv_pairs.append((k_str, val_s))
                elif isinstance(v, (dict, list)):
                    _walk(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:6]:
                if isinstance(item, (dict, list)):
                    _walk(item, depth + 1)

    if req_json is not None:
        _walk(req_json, 0)
    return path_set, kv_pairs


def _detect_mutation_targets(
    method: str,
    url_path: str,
    query_keys: Sequence[str],
    json_template: Any,
    *,
    form_template: dict[str, Any] | None = None,
    xml_tags: Sequence[str] = (),
    body_kind: str = "",
) -> list[str]:
    """Identify business-logic numeric/role/status/owner fields and race-prone endpoints."""
    targets: list[str] = []
    seen: set[str] = set()

    def _add(label: str) -> None:
        if label and label not in seen:
            seen.add(label)
            targets.append(label)

    def _check_key(key: str) -> None:
        snake, tokens = _to_snake_tokens(key)
        if not snake:
            return
        if (
            snake in _NUMERIC_LOGIC_TOKENS
            or snake in _ROLE_STATUS_TOKENS
            or snake in _OWNER_BOLA_TOKENS
            or any(tok in _NUMERIC_LOGIC_TOKENS or tok in _ROLE_STATUS_TOKENS for tok in tokens)
        ):
            _add(key)

    for qk in query_keys:
        _check_key(qk)

    def _walk_json(node: Any, depth: int) -> None:
        if depth > 5:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                _check_key(str(k))
                if isinstance(v, (dict, list)):
                    _walk_json(v, depth + 1)
        elif isinstance(node, list):
            for item in node[:6]:
                if isinstance(item, (dict, list)):
                    _walk_json(item, depth + 1)

    if json_template is not None:
        _walk_json(json_template, 0)

    if isinstance(form_template, dict):
        for fk in form_template:
            _check_key(str(fk))

    if xml_tags or body_kind == "xml":
        _add("xml")
        for tag in xml_tags:
            local_tag = str(tag).split(":", 1)[-1].strip()
            if local_tag:
                _check_key(local_tag)

    if method in _WRITE_METHODS:
        low_path = url_path.lower()
        path_parts = [seg for seg in low_path.split("/") if seg]
        expanded_parts: set[str] = set(path_parts)
        for seg in path_parts:
            expanded_parts.update(tok for tok in _TOKEN_SPLIT_RE.split(seg) if tok)
        for raw_marker, canonical in _RACE_PATH_TOKENS:
            if raw_marker in path_parts or raw_marker in expanded_parts or raw_marker in low_path:
                _add(canonical)

    return targets


def _parse_iso_timestamp(raw: Any) -> float | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def _is_static_har_entry(url: str, path: str, method: str, resp_mime: str) -> bool:
    low_path = path.lower().rstrip("/")
    if any(low_path.endswith(ext) for ext in _HAR_STATIC_EXTENSIONS):
        return True
    if is_static_asset_url(url):
        return True
    if method == "GET" and resp_mime:
        if resp_mime.startswith(_STATIC_RESPONSE_MIME_PREFIXES) or resp_mime in _STATIC_RESPONSE_MIMES:
            return True
    return False


def _format_step_url(
    scheme: str,
    host: str,
    port: int,
    norm_path: str,
    base_origin_key: tuple[str, str, int],
) -> str:
    if (scheme, host, port) == base_origin_key:
        return norm_path
    host_part = f"[{host}]" if ":" in host else host
    if port == _default_port(scheme):
        return f"{scheme}://{host_part}{norm_path}"
    return f"{scheme}://{host_part}:{port}{norm_path}"


def _resource_root(path: str) -> str:
    segs = [seg.lower() for seg in path.split("/") if seg]
    while segs and segs[0] in {"api", "bff", "rest", "rpc", "ajax", "v1", "v2", "v3", "v4"}:
        segs.pop(0)
    return segs[0] if segs else "/"


def _is_terminal_step(step_rec: dict[str, Any]) -> bool:
    path_low = str(step_rec.get("path") or "").lower()
    tokens = {tok for tok in _TOKEN_SPLIT_RE.split(path_low) if tok}
    return bool(tokens & _TERMINAL_PATH_TOKENS)


def _group_steps_into_flows(
    candidates: list[dict[str, Any]],
    *,
    max_flows: int,
    max_steps_per_flow: int,
) -> list[list[dict[str, Any]]]:
    """Group ordered steps into bounded sequential workflows while keeping chained chains intact."""
    if not candidates:
        return []

    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_indices: set[int] = set()
    current_had_terminal = False
    current_roots: set[str] = set()

    for cand in candidates:
        raw_idx = int(cand["_raw_idx"])
        upstream_indices = set(cand["_raw_chained_from"])
        is_chained_to_current = bool(upstream_indices & current_indices)
        cand_root = _resource_root(cand["path"])
        prev_ts = current[-1]["_ts"] if current else None
        cur_ts = cand["_ts"]
        large_time_gap = (
            prev_ts is not None
            and cur_ts is not None
            and (cur_ts - prev_ts) > 120.0
        )

        should_split = False
        if len(current) >= max_steps_per_flow:
            should_split = True
        elif current and not is_chained_to_current:
            if large_time_gap:
                should_split = True
            elif (
                current_had_terminal
                and cand_root not in current_roots
                and cand["method"] == "GET"
            ):
                should_split = True

        if should_split and current:
            groups.append(current)
            current = []
            current_indices = set()
            current_had_terminal = False
            current_roots = set()

        current.append(cand)
        current_indices.add(raw_idx)
        current_roots.add(cand_root)
        if _is_terminal_step(cand):
            current_had_terminal = True

    if current:
        groups.append(current)

    def _flow_score(group: list[dict[str, Any]]) -> tuple[int, int, int, int]:
        mutations = sum(1 for item in group if item["method"] in _WRITE_METHODS)
        chains = sum(1 for item in group if item["_raw_chained_from"])
        targets = sum(len(item["mutation_targets"]) for item in group)
        return (chains * 3 + mutations * 2 + targets, len(group), -group[0]["_raw_idx"], 0)

    if len(groups) > max_flows:
        ranked = sorted(groups, key=_flow_score, reverse=True)[:max_flows]
        ranked.sort(key=lambda grp: grp[0]["_raw_idx"])
        return ranked
    return groups


def _build_recommended_app_headers(steps: Sequence[dict[str, Any]]) -> dict[str, str]:
    """Aggregate fixed non-auth application headers seen consistently on API calls."""
    api_steps = [
        s for s in steps
        if (
            s["method"] in _WRITE_METHODS
            or s["json_template"] is not None
            or s.get("form_template") is not None
            or s.get("body_kind") in {"json", "form", "xml", "raw"}
            or _API_STEP_PATH_RE.search(s["path"])
            or "bff" in s["host"]
        )
    ]
    sample = api_steps or list(steps)
    if not sample:
        return {}

    counts: dict[str, dict[str, int]] = {}
    canonical_names: dict[str, str] = {}
    for s in sample:
        for k, v in (s.get("required_app_headers") or {}).items():
            low = k.lower()
            canonical_names.setdefault(low, k)
            val_counts = counts.setdefault(low, {})
            val_counts[v] = val_counts.get(v, 0) + 1

    min_count = 2 if len(sample) >= 2 else 1
    recommended: dict[str, str] = {}
    for low, val_counts in counts.items():
        best_val, best_count = max(val_counts.items(), key=lambda kv: (kv[1], kv[0]))
        total_for_key = sum(val_counts.values())
        if best_count >= min_count and (best_count * 2) >= total_for_key:
            recommended[canonical_names[low]] = best_val
        if len(recommended) >= 12:
            break
    return recommended


def extract_har_flows(
    har_path_or_dict: Path | str | dict[str, Any],
    *,
    base_url: str,
    excluded_paths: Sequence[str] = (),
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
    max_flows: int = MAX_HAR_FLOWS,
    max_steps_per_flow: int = MAX_STEPS_PER_FLOW,
) -> dict[str, Any]:
    """Extract scope-filtered, secret-redacted stateful API workflows from a HAR archive."""
    har_doc = _load_har_source(har_path_or_dict)
    guard = ScopeGuard(
        base_origin=base_url,
        excluded_paths=tuple(excluded_paths or ()),
        in_scope_assets=tuple(in_scope_assets or ()),
        out_of_scope_assets=tuple(out_of_scope_assets or ()),
    )
    base_origin_key = guard._origin_key
    cap_flows = max(1, int(max_flows))
    cap_steps = max(1, int(max_steps_per_flow))

    entries = har_doc["log"]["entries"]
    entries_total = len(entries)
    dropped_scope = 0
    dropped_static = 0
    dropped_noise = 0

    candidates: list[dict[str, Any]] = []
    seen_readonly_keys: set[tuple[str, str, tuple[str, ...]]] = set()

    for entry in entries:
        if not isinstance(entry, dict):
            dropped_noise += 1
            continue
        req = entry.get("request")
        if not isinstance(req, dict):
            dropped_noise += 1
            continue
        raw_url = str(req.get("url") or "").strip()
        if not raw_url:
            dropped_noise += 1
            continue
        method = str(req.get("method") or "GET").strip().upper()
        if method not in _ALLOWED_FLOW_METHODS:
            dropped_noise += 1
            continue

        try:
            parsed = urlsplit(raw_url)
        except ValueError:
            dropped_scope += 1
            continue
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.username is not None or parsed.password is not None:
            dropped_scope += 1
            continue
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            dropped_scope += 1
            continue
        try:
            port = parsed.port if parsed.port is not None else _default_port(scheme)
        except ValueError:
            dropped_scope += 1
            continue

        try:
            guard.check_url(raw_url)
            norm_path = normalize_path(parsed.path or "/")
        except ValueError:
            dropped_scope += 1
            continue

        raw_resp = entry.get("response")
        resp: dict[str, Any] = raw_resp if isinstance(raw_resp, dict) else {}
        resp_status_raw = resp.get("status")
        resp_status = (
            int(resp_status_raw)
            if isinstance(resp_status_raw, int) and not isinstance(resp_status_raw, bool)
            else 0
        )
        raw_resp_content = resp.get("content")
        resp_content: dict[str, Any] = raw_resp_content if isinstance(raw_resp_content, dict) else {}
        resp_mime = str(resp_content.get("mimeType") or "").split(";", 1)[0].strip().lower()

        if _is_static_har_entry(raw_url, norm_path, method, resp_mime):
            dropped_static += 1
            continue

        # Collect query keys (names only in final step; values kept strictly ephemeral for ID chaining).
        query_pairs: list[tuple[str, str]] = []
        query_keys: list[str] = []
        seen_qk: set[str] = set()
        for qk, qv in parse_qsl(parsed.query, keep_blank_values=True):
            clean_qk = qk.strip()
            if clean_qk and not _has_control_chars(clean_qk):
                query_pairs.append((clean_qk, qv))
                if clean_qk not in seen_qk:
                    seen_qk.add(clean_qk)
                    query_keys.append(clean_qk)
        if isinstance(req.get("queryString"), list):
            for q_item in req["queryString"]:
                if not isinstance(q_item, dict):
                    continue
                qk_raw = q_item.get("name")
                qv_raw = q_item.get("value")
                if isinstance(qk_raw, str):
                    clean_qk = qk_raw.strip()
                    if clean_qk and not _has_control_chars(clean_qk):
                        if isinstance(qv_raw, str):
                            query_pairs.append((clean_qk, qv_raw))
                        if clean_qk not in seen_qk:
                            seen_qk.add(clean_qk)
                            query_keys.append(clean_qk)

        app_headers = _sanitize_app_headers(req.get("headers"))
        raw_post_data = req.get("postData")
        post_data: dict[str, Any] = raw_post_data if isinstance(raw_post_data, dict) else {}
        raw_ct = str(
            post_data.get("mimeType") or _header_value_ci(app_headers, "content-type") or ""
        ).split(";", 1)[0].strip().lower()
        req_text = _decode_har_text_payload(post_data) if post_data else ""
        req_json = _parse_json_payload(req_text) if req_text else None
        json_template = _sanitize_json_value(req_json) if req_json is not None else None
        form_template: dict[str, str] | None = None
        raw_form_pairs: list[tuple[str, str]] = []
        xml_tags: list[str] = []
        body_kind = ""
        if req_json is not None:
            body_kind = "json"
        elif (
            "x-www-form-urlencoded" in raw_ct
            or (
                isinstance(post_data.get("params"), list)
                and bool(post_data.get("params"))
                and "multipart" not in raw_ct
            )
        ):
            raw_form_pairs, parsed_form = _parse_form_payload(post_data, req_text)
            if parsed_form:
                form_template = parsed_form
                body_kind = "form"
        elif (
            raw_ct in _XML_CONTENT_TYPES
            or raw_ct.endswith("+xml")
            or (
                req_text.lstrip().startswith("<")
                and not raw_ct
                and not req_text.lstrip().lower().startswith(("<!doctype html", "<html"))
            )
        ):
            xml_tags = _extract_xml_tags(req_text)
            body_kind = "xml"
        elif "text/plain" in raw_ct or bool(req_text.strip()):
            body_kind = "raw"

        resp_text = _decode_har_text_payload(resp_content) if resp_content else ""
        resp_json = _parse_json_payload(resp_text) if resp_text else None
        produced_candidates = _extract_response_id_candidates(resp_json) if resp_json is not None else []

        step_url = _format_step_url(scheme, host, port, norm_path, base_origin_key)
        readonly_key = (method, step_url, tuple(sorted(query_keys)))
        if method == "GET" and not produced_candidates and readonly_key in seen_readonly_keys:
            dropped_noise += 1
            continue
        if method == "GET":
            seen_readonly_keys.add(readonly_key)

        path_segments = [seg for seg in norm_path.split("/") if seg]
        req_path_set, req_kv_pairs = _collect_request_scalars(
            path_segments,
            [*query_pairs, *raw_form_pairs],
            req_json,
        )
        mutation_targets = _detect_mutation_targets(
            method,
            norm_path,
            query_keys,
            json_template,
            form_template=form_template,
            xml_tags=xml_tags,
            body_kind=body_kind,
        )

        candidates.append({
            "_raw_idx": len(candidates),
            "_ts": _parse_iso_timestamp(entry.get("startedDateTime")),
            "_produced_candidates": produced_candidates,
            "_produced_fields_ordered": [],
            "_req_path_set": req_path_set,
            "_req_kv_pairs": req_kv_pairs,
            "_raw_chained_from": [],
            "_raw_chained_fields": [],
            "host": host,
            "path": norm_path,
            "method": method,
            "url": step_url,
            "query_keys": query_keys,
            "content_type": raw_ct,
            "body_kind": body_kind,
            "required_app_headers": app_headers,
            "json_template": json_template,
            "form_template": form_template,
            "xml_tags": xml_tags,
            "response_status": resp_status,
            "mutation_targets": mutation_targets,
        })

    # Detect cross-step ID production & consumption across accepted candidates.
    for j, cur in enumerate(candidates):
        cur_path_set: set[str] = cur["_req_path_set"]
        cur_kv_pairs: list[tuple[str, str]] = cur["_req_kv_pairs"]
        matched_producers: list[int] = []
        matched_fields: list[str] = []

        for qk, qv in cur_kv_pairs:
            # Find earliest upstream step producing this value.
            for i in range(j):
                prod = candidates[i]
                hit_field = ""
                for prod_key, prod_val, req_strict in prod["_produced_candidates"]:
                    if qv != prod_val:
                        continue
                    if req_strict:
                        qk_snake, _ = _to_snake_tokens(qk)
                        pk_snake, _ = _to_snake_tokens(prod_key)
                        if qk_snake != pk_snake and qk_snake not in {"id", pk_snake}:
                            continue
                    hit_field = prod_key
                    break
                if hit_field:
                    if hit_field not in prod["_produced_fields_ordered"]:
                        prod["_produced_fields_ordered"].append(hit_field)
                    if i not in matched_producers:
                        matched_producers.append(i)
                    if hit_field not in matched_fields:
                        matched_fields.append(hit_field)
                    break

        for seg in cur_path_set:
            for i in range(j):
                prod = candidates[i]
                hit_field = ""
                for prod_key, prod_val, _ in prod["_produced_candidates"]:
                    if seg == prod_val:
                        hit_field = prod_key
                        break
                if hit_field:
                    if hit_field not in prod["_produced_fields_ordered"]:
                        prod["_produced_fields_ordered"].append(hit_field)
                    if i not in matched_producers:
                        matched_producers.append(i)
                    if hit_field not in matched_fields:
                        matched_fields.append(hit_field)
                    break

        cur["_raw_chained_from"] = matched_producers
        cur["_raw_chained_fields"] = matched_fields

    grouped = _group_steps_into_flows(
        candidates,
        max_flows=cap_flows,
        max_steps_per_flow=cap_steps,
    )

    flows: list[dict[str, Any]] = []
    all_kept_steps: list[dict[str, Any]] = []
    chained_steps_count = 0

    for flow_num, group in enumerate(grouped, start=1):
        raw_to_step_idx = {
            int(item["_raw_idx"]): idx for idx, item in enumerate(group, start=1)
        }
        flow_steps: list[dict[str, Any]] = []
        flow_origins: list[str] = []
        seen_origins: set[str] = set()
        name_parts: list[str] = []

        for step_idx, item in enumerate(group, start=1):
            in_flow_chains = [
                raw_to_step_idx[up]
                for up in item["_raw_chained_from"]
                if up in raw_to_step_idx
            ]
            chained_from_step = max(in_flow_chains) if in_flow_chains else None
            if chained_from_step is not None:
                chained_steps_count += 1

            step_obj: dict[str, Any] = {
                "step_index": step_idx,
                "method": item["method"],
                "url": item["url"],
                "query_keys": list(item["query_keys"]),
                "content_type": item["content_type"],
                "body_kind": item["body_kind"],
                "required_app_headers": dict(item["required_app_headers"]),
                "json_template": copy.deepcopy(item["json_template"]),
                "form_template": copy.deepcopy(item["form_template"]),
                "xml_tags": list(item["xml_tags"]),
                "response_status": item["response_status"],
                "produced_id_fields": list(item["_produced_fields_ordered"]),
                "chained_from_step": chained_from_step,
                "chained_from_steps": in_flow_chains,
                "chained_fields": list(item["_raw_chained_fields"]) if in_flow_chains else [],
                "mutation_targets": list(item["mutation_targets"]),
                # Keep lightweight internal attributes for header aggregation
                "path": item["path"],
                "host": item["host"],
            }
            flow_steps.append(step_obj)
            all_kept_steps.append(step_obj)
            if item["host"] not in seen_origins:
                seen_origins.add(item["host"])
                flow_origins.append(item["host"])
            root_seg = _resource_root(item["path"])
            if root_seg != "/" and root_seg not in name_parts:
                name_parts.append(root_seg)

        # Remove internal routing keys after keeping flow steps clean? Wait: keeping path/host clean or stripping?
        # Keep flow steps crisp & clean while building recommended headers first.
        flow_name = " -> ".join(name_parts[:4]) if name_parts else f"flow_{flow_num}"
        flows.append({
            "flow_id": f"flow_{flow_num}",
            "name": flow_name,
            "origins": flow_origins,
            "has_mutations": any(s["method"] in _WRITE_METHODS for s in flow_steps),
            "has_chaining": any(s["chained_from_step"] is not None for s in flow_steps),
            "steps": flow_steps,
        })

    recommended_app_headers = _build_recommended_app_headers(all_kept_steps)
    for step_obj in all_kept_steps:
        step_obj.pop("path", None)
        step_obj.pop("host", None)

    mutation_cases = build_flow_mutation_cases(flows)
    return {
        "schema": HAR_FLOW_SCHEMA,
        "base_url": guard.base_origin,
        "flows": flows,
        "recommended_app_headers": recommended_app_headers,
        "mutation_cases": mutation_cases,
        "stats": {
            "entries_total": entries_total,
            "entries_accepted": len(candidates),
            "entries_dropped_scope": dropped_scope,
            "entries_dropped_static": dropped_static,
            "entries_dropped_noise": dropped_noise,
            "flows_count": len(flows),
            "steps_count": len(all_kept_steps),
            "chained_steps_count": chained_steps_count,
        },
    }


def _collect_json_field_paths(node: Any, prefix: str = "") -> list[tuple[str, Any]]:
    items: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            key_s = str(k)
            full = f"{prefix}.{key_s}" if prefix else key_s
            if isinstance(v, dict):
                items.extend(_collect_json_field_paths(v, full))
            else:
                items.append((key_s, v))
    return items


def build_flow_mutation_cases(
    flows_or_doc: Sequence[dict[str, Any]] | dict[str, Any],
    *,
    max_cases: int = 40,
) -> list[dict[str, Any]]:
    """Generate concrete, non-destructive security & business-logic mutation test cases."""
    if isinstance(flows_or_doc, dict):
        raw_flows = flows_or_doc.get("flows") or []
    else:
        raw_flows = flows_or_doc or []

    cases: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    cap = max(1, int(max_cases))

    def _push(case: dict[str, Any]) -> None:
        if len(cases) >= cap:
            return
        dedup_key = (
            str(case.get("category") or ""),
            str(case.get("method") or ""),
            str(case.get("url") or ""),
            str(case.get("target_field") or ""),
        )
        if dedup_key in seen_keys:
            return
        seen_keys.add(dedup_key)
        cases.append(case)

    for flow in raw_flows:
        if not isinstance(flow, dict):
            continue
        flow_id = str(flow.get("flow_id") or "")
        for step in flow.get("steps") or []:
            if not isinstance(step, dict):
                continue
            method = str(step.get("method") or "GET").upper()
            url = str(step.get("url") or "")
            step_index = int(step.get("step_index") or 0)
            json_tmpl = step.get("json_template")
            form_tmpl = step.get("form_template")
            xml_tags = [str(t) for t in (step.get("xml_tags") or []) if str(t).strip()]
            body_kind = str(step.get("body_kind") or "").strip().lower()
            targets = [str(t) for t in (step.get("mutation_targets") or [])]
            headers = dict(step.get("required_app_headers") or {})

            # 1. Business-logic numeric tampering (negative / zero quantity, price, amount, discount, points)
            if isinstance(json_tmpl, dict):
                for key, val in _collect_json_field_paths(json_tmpl):
                    snake, tokens = _to_snake_tokens(key)
                    if snake in _NUMERIC_LOGIC_TOKENS or any(tok in _NUMERIC_LOGIC_TOKENS for tok in tokens):
                        if isinstance(val, (int, float)) and not isinstance(val, bool):
                            _push({
                                "flow_id": flow_id,
                                "step_index": step_index,
                                "category": "business_logic_numeric",
                                "tool": "http_request",
                                "method": method,
                                "url": url,
                                "target_field": key,
                                "json_overrides": {key: -1},
                                "zero_override": {key: 0},
                                "required_app_headers": headers,
                                "description": f"Test negative/zero {key} validation on {method} {url}",
                            })

                    # 2. Mass assignment / privilege or status tamper
                    if snake in _ROLE_STATUS_TOKENS or any(tok in _ROLE_STATUS_TOKENS for tok in tokens):
                        tamper_val: Any = True if isinstance(val, bool) or "admin" in snake else "admin"
                        if "status" in snake or "state" in snake:
                            tamper_val = "paid"
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "mass_assignment",
                            "tool": "http_request",
                            "method": method,
                            "url": url,
                            "target_field": key,
                            "json_overrides": {key: tamper_val},
                            "required_app_headers": headers,
                            "description": f"Test privilege/status mass assignment via {key} on {method} {url}",
                        })

                    # 3. Owner / tenant field tampering (IDOR/BOLA via body parameter)
                    if snake in _OWNER_BOLA_TOKENS:
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "idor_owner_tamper",
                            "tool": "replay_as",
                            "method": method,
                            "url": url,
                            "target_field": key,
                            "json_overrides": {key: val},
                            "required_app_headers": headers,
                            "description": f"Test cross-actor owner/tenant tampering via {key} on {method} {url}",
                        })

            # 1b. Form-urlencoded mutation cases (numeric, mass assignment, owner/tenant tamper)
            if isinstance(form_tmpl, dict) and form_tmpl:
                for key, val in form_tmpl.items():
                    snake, tokens = _to_snake_tokens(str(key))
                    val_str = str(val or "").strip()
                    if snake in _NUMERIC_LOGIC_TOKENS or any(tok in _NUMERIC_LOGIC_TOKENS for tok in tokens):
                        if (isinstance(val, (int, float)) and not isinstance(val, bool)) or _NUMERIC_STR_RE.fullmatch(val_str):
                            _push({
                                "flow_id": flow_id,
                                "step_index": step_index,
                                "category": "business_logic_numeric",
                                "tool": "http_request",
                                "method": method,
                                "url": url,
                                "target_field": str(key),
                                "form_overrides": {str(key): "-1"},
                                "zero_override": {str(key): "0"},
                                "required_app_headers": headers,
                                "description": f"Test negative/zero form field {key} validation on {method} {url}",
                            })
                    if snake in _ROLE_STATUS_TOKENS or any(tok in _ROLE_STATUS_TOKENS for tok in tokens):
                        form_tamper = "true" if (val_str.lower() in {"true", "false"} or "admin" in snake) else "admin"
                        if "status" in snake or "state" in snake:
                            form_tamper = "paid"
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "mass_assignment",
                            "tool": "http_request",
                            "method": method,
                            "url": url,
                            "target_field": str(key),
                            "form_overrides": {str(key): form_tamper},
                            "required_app_headers": headers,
                            "description": f"Test form privilege/status mass assignment via {key} on {method} {url}",
                        })
                    if snake in _OWNER_BOLA_TOKENS:
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "idor_owner_tamper",
                            "tool": "replay_as",
                            "method": method,
                            "url": url,
                            "target_field": str(key),
                            "form_overrides": {str(key): val_str},
                            "required_app_headers": headers,
                            "description": f"Test cross-actor form owner/tenant tampering via {key} on {method} {url}",
                        })

            # 1c. XML / XXE and XML element mutation cases
            if body_kind == "xml" or xml_tags:
                tag_preview = ",".join(xml_tags[:4]) if xml_tags else "xml"
                _push({
                    "flow_id": flow_id,
                    "step_index": step_index,
                    "category": "xml_injection",
                    "tool": "http_request",
                    "method": method,
                    "url": url,
                    "target_field": tag_preview,
                    "body_kind": "xml",
                    "xml_tags": list(xml_tags[:8]),
                    "required_app_headers": headers,
                    "description": f"Test XML/XXE entity handling on {method} {url} (tags: {tag_preview})",
                })
                for tag in xml_tags:
                    local_tag = tag.split(":", 1)[-1].strip()
                    snake, tokens = _to_snake_tokens(local_tag)
                    if snake in _NUMERIC_LOGIC_TOKENS or any(tok in _NUMERIC_LOGIC_TOKENS for tok in tokens):
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "business_logic_numeric",
                            "tool": "http_request",
                            "method": method,
                            "url": url,
                            "target_field": local_tag,
                            "body_kind": "xml",
                            "required_app_headers": headers,
                            "description": f"Test negative/zero XML element <{local_tag}> validation on {method} {url}",
                        })
                    if snake in _ROLE_STATUS_TOKENS or any(tok in _ROLE_STATUS_TOKENS for tok in tokens):
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "mass_assignment",
                            "tool": "http_request",
                            "method": method,
                            "url": url,
                            "target_field": local_tag,
                            "body_kind": "xml",
                            "required_app_headers": headers,
                            "description": f"Test privilege/status tampering via XML element <{local_tag}> on {method} {url}",
                        })
                    if snake in _OWNER_BOLA_TOKENS:
                        _push({
                            "flow_id": flow_id,
                            "step_index": step_index,
                            "category": "idor_owner_tamper",
                            "tool": "replay_as",
                            "method": method,
                            "url": url,
                            "target_field": local_tag,
                            "body_kind": "xml",
                            "required_app_headers": headers,
                            "description": f"Test cross-actor owner/tenant tampering via XML element <{local_tag}> on {method} {url}",
                        })

            # Implicit mass-assignment probe on user/profile/account writes lacking explicit role fields
            if method in {"POST", "PUT", "PATCH"} and (isinstance(json_tmpl, dict) or isinstance(form_tmpl, dict)):
                low_url = url.lower()
                if any(tok in low_url for tok in ("/profile", "/account", "/users", "/register", "/me")):
                    case_obj: dict[str, Any] = {
                        "flow_id": flow_id,
                        "step_index": step_index,
                        "category": "mass_assignment",
                        "tool": "http_request",
                        "method": method,
                        "url": url,
                        "target_field": "role,isAdmin",
                        "required_app_headers": headers,
                        "description": f"Probe hidden role/isAdmin mass assignment on {method} {url}",
                    }
                    if isinstance(json_tmpl, dict):
                        case_obj["json_overrides"] = {"role": "admin", "isAdmin": True}
                    else:
                        case_obj["form_overrides"] = {"role": "admin", "isAdmin": "true"}
                    _push(case_obj)

            # 4. Concurrent race check on one-shot / state-changing endpoints
            if method in _WRITE_METHODS:
                low_path = urlsplit(url).path.lower()
                race_hits = [
                    canonical for raw_m, canonical in _RACE_PATH_TOKENS
                    if raw_m in low_path or canonical in targets
                ]
                if race_hits:
                    race_case: dict[str, Any] = {
                        "flow_id": flow_id,
                        "step_index": step_index,
                        "category": "concurrent_race",
                        "tool": "concurrent_check",
                        "method": method,
                        "url": url,
                        "target_field": race_hits[0],
                        "concurrency": 5,
                        "json_template": copy.deepcopy(json_tmpl) if isinstance(json_tmpl, dict) else None,
                        "required_app_headers": headers,
                        "description": f"Run concurrent_check for TOCTOU/double-spend on {method} {url}",
                    }
                    if isinstance(form_tmpl, dict) and form_tmpl:
                        race_case["form_template"] = copy.deepcopy(form_tmpl)
                    _push(race_case)

            # 5. Cross-actor replay (BOLA / BFLA) on chained, ID-bearing, or state-changing steps
            has_id_seg = any(is_id_segment(seg) for seg in urlsplit(url).path.split("/") if seg)
            if step.get("chained_from_step") is not None or has_id_seg or method in _WRITE_METHODS:
                _push({
                    "flow_id": flow_id,
                    "step_index": step_index,
                    "category": "cross_actor_replay",
                    "tool": "replay_as",
                    "method": method,
                    "url": url,
                    "target_field": "actor",
                    "required_app_headers": headers,
                    "description": f"Replay {method} {url} as peer actor (BOLA) and anon (BFLA)",
                })

            if len(cases) >= cap:
                break
        if len(cases) >= cap:
            break

    return cases[:cap]


def format_har_flows_handoff(
    flow_doc: dict[str, Any] | Sequence[dict[str, Any]],
    *,
    max_chars: int = 2400,
) -> str:
    """Format extracted HAR workflows into a compact, secret-free prompt handoff string."""
    budget = max(80, int(max_chars))
    if isinstance(flow_doc, dict):
        flows = flow_doc.get("flows") or []
        rec_headers = _sanitize_app_headers(flow_doc.get("recommended_app_headers") or {})
        cases = flow_doc.get("mutation_cases")
        if not isinstance(cases, list):
            cases = build_flow_mutation_cases(flows)
    else:
        flows = list(flow_doc or [])
        rec_headers = {}
        cases = build_flow_mutation_cases(flows)

    lines: list[str] = ["HAR Multi-Step Flows (credentials redacted):"]
    if rec_headers:
        hdr_text = ", ".join(f"{k}={v}" for k, v in rec_headers.items())
        lines.append(f"App Headers: {hdr_text}")

    for flow in flows:
        if not isinstance(flow, dict):
            continue
        fid = str(flow.get("flow_id") or "flow")
        fname = str(flow.get("name") or "")
        lines.append(f"[{fid}] {fname}".strip())
        for step in flow.get("steps") or []:
            if not isinstance(step, dict):
                continue
            idx = step.get("step_index", "?")
            method = str(step.get("method") or "GET")
            url = str(step.get("url") or "/")
            status = step.get("response_status")
            meta_parts: list[str] = []
            if status:
                meta_parts.append(f"status={status}")
            if step.get("chained_from_step") is not None:
                meta_parts.append(f"from_step={step['chained_from_step']}")
            if step.get("produced_id_fields"):
                meta_parts.append("produces=" + ",".join(str(x) for x in step["produced_id_fields"][:4]))
            if step.get("query_keys"):
                meta_parts.append("query=" + ",".join(str(x) for x in step["query_keys"][:6]))
            if step.get("mutation_targets"):
                meta_parts.append("targets=" + ",".join(str(x) for x in step["mutation_targets"][:6]))
            tmpl = step.get("json_template")
            if isinstance(tmpl, dict) and tmpl:
                sanitized_tmpl = _sanitize_json_value(tmpl)
                tmpl_str = json.dumps(sanitized_tmpl, ensure_ascii=False, separators=(",", ":"))
                if len(tmpl_str) > 140:
                    tmpl_str = tmpl_str[:137] + "..."
                meta_parts.append(f"json={tmpl_str}")
            form_tmpl = step.get("form_template")
            if isinstance(form_tmpl, dict) and form_tmpl:
                sanitized_form = _sanitize_form_template(form_tmpl)
                form_str = json.dumps(sanitized_form, ensure_ascii=False, separators=(",", ":"))
                if len(form_str) > 140:
                    form_str = form_str[:137] + "..."
                meta_parts.append(f"form={form_str}")
            step_xml_tags = [str(t)[:32] for t in (step.get("xml_tags") or []) if str(t).strip()]
            step_body_kind = str(step.get("body_kind") or "").strip().lower()
            if step_xml_tags:
                meta_parts.append("xml_tags=" + ",".join(step_xml_tags[:8]))
            elif step_body_kind in {"xml", "raw"}:
                meta_parts.append(f"body_kind={step_body_kind}")
            suffix = f" ({'; '.join(meta_parts)})" if meta_parts else ""
            lines.append(f"  {idx}. {method} {url}{suffix}")

    if cases:
        lines.append("Priority Mutations:")
        for case in cases[:6]:
            if not isinstance(case, dict):
                continue
            cat = str(case.get("category") or "")
            desc = str(case.get("description") or "")
            lines.append(f"  - [{cat}] {desc}")

    rendered = "\n".join(lines)
    if len(rendered) <= budget:
        return rendered
    return rendered[: max(0, budget - 3)].rstrip() + "..."


def _deep_merge_json(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_json(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def replay_har_flow_step(
    http_client: Any,
    step: dict[str, Any],
    *,
    actor: str = "anon",
    json_overrides: dict[str, Any] | None = None,
    form_overrides: dict[str, Any] | None = None,
    header_overrides: dict[str, Any] | None = None,
    query_overrides: dict[str, Any] | None = None,
    url_override: str | None = None,
    force: bool = True,
) -> dict[str, Any]:
    """Replay an extracted HAR flow step safely via `AgenticHTTPClient.request(...)`."""
    if not isinstance(step, dict):
        raise ValueError("step must be a dict")
    method = str(step.get("method") or "GET").strip().upper()
    target_url = str(url_override or step.get("url") or "").strip()
    if not target_url:
        raise ValueError("step URL is required")

    merged_headers = _sanitize_app_headers(step.get("required_app_headers") or {})
    if isinstance(header_overrides, dict):
        for raw_k, raw_v in header_overrides.items():
            key_s = str(raw_k).strip()
            if not key_s or _has_control_chars(key_s):
                continue
            key_low = key_s.lower()
            for existing in [ek for ek in merged_headers if ek.lower() == key_low and ek != key_s]:
                merged_headers.pop(existing, None)
            if raw_v is None or str(raw_v) == "":
                merged_headers.pop(key_s, None)
            else:
                val_s = str(raw_v).strip()
                if not _has_control_chars(val_s):
                    merged_headers[key_s] = val_s

    json_body: Any = None
    base_tmpl = step.get("json_template")
    if isinstance(base_tmpl, dict) and isinstance(json_overrides, dict):
        json_body = _deep_merge_json(base_tmpl, json_overrides)
    elif isinstance(json_overrides, dict):
        json_body = copy.deepcopy(json_overrides)
    elif base_tmpl is not None and form_overrides is None:
        json_body = copy.deepcopy(base_tmpl)

    form_body: dict[str, Any] | None = None
    base_form = step.get("form_template")
    is_form_step = isinstance(base_form, dict) or str(step.get("body_kind") or "").strip().lower() == "form"
    if json_body is None and (is_form_step or isinstance(form_overrides, dict)):
        merged_form: dict[str, Any] = copy.deepcopy(base_form) if isinstance(base_form, dict) else {}
        if isinstance(form_overrides, dict):
            merged_form.update(copy.deepcopy(form_overrides))
        if merged_form or isinstance(form_overrides, dict):
            form_body = merged_form

    if json_body is not None:
        ct_key = next((k for k in merged_headers if k.lower() == "content-type"), None)
        if ct_key is not None and "json" not in merged_headers[ct_key].lower():
            merged_headers.pop(ct_key, None)
    elif form_body is not None:
        ct_key = next((k for k in merged_headers if k.lower() == "content-type"), None)
        if ct_key is not None and "x-www-form-urlencoded" not in merged_headers[ct_key].lower():
            merged_headers.pop(ct_key, None)

    req_kwargs: dict[str, Any] = {
        "method": method,
        "url": target_url,
        "actor": actor,
        "headers": merged_headers or None,
        "query": query_overrides,
        "json_body": json_body,
        "force": bool(force),
    }
    if form_body is not None:
        req_kwargs["form_body"] = form_body

    return http_client.request(**req_kwargs)
