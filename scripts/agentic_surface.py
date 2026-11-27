"""General-purpose passive attack-surface and depth frontier tracker.

Passively extracts routes, forms/parameters, concrete resource object URLs,
write operations, and actor coverage from every HTTP receipt at 0 extra HTTP cost.
"""
from __future__ import annotations

from html import unescape
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from agentic_http import is_static_asset_url, normalize_origin

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from kryon_core.surface.extract import (  # noqa: E402
    _BUNDLER_EXACT_PATHS as _BUNDLER_EXACT_PATHS,
    _BUNDLER_PATH_MARKERS as _BUNDLER_PATH_MARKERS,
    _FRONTEND_SOURCE_DIR_PREFIXES as _FRONTEND_SOURCE_DIR_PREFIXES,
    _NON_ENDPOINT_SOURCE_EXTS as _NON_ENDPOINT_SOURCE_EXTS,
    extract_html,
    extract_inline_scripts,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_robots,
    extract_sitemap,
    extract_spa_routes,
    find_spec_urls,
    has_double_slash_path,
    is_hashed_asset_chunk_path,
    is_non_endpoint_noise_path,
)
from kryon_core.surface.normalize import (  # noqa: E402
    is_os_filesystem_path,
    is_port_in_path_artifact,
    normalize_bare_hostport_url,
)
from kryon_core.surface.openapi import LocalSchema  # noqa: E402
from target_bootstrap import ScopeGuard  # noqa: E402

_UUID_SEG_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_ID_SEG_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_PREFIXED_ID_SEG_RE = re.compile(r"^[a-z]{1,12}[-_][0-9a-z_-]*\d[0-9a-z_-]*$", re.I)
_TEMPLATE_SEG_RE = re.compile(r"^\{[^}]+\}$")
_AUTH_PATH_TOKENS = (
    "sign-in",
    "signin",
    "sign-out",
    "signout",
    "sign-up",
    "signup",
    "register",
    "login",
    "log-in",
    "logout",
    "log-out",
    "refresh",
    "session",
)
_VIRGIN_STATE_SENSITIVE_TOKENS = frozenset({
    "claim",
    "redeem",
    "promo",
    "promos",
    "coupon",
    "coupons",
    "voucher",
    "vouchers",
    "bonus",
    "reward",
    "rewards",
    "vote",
    "checkin",
    "check-in",
    "withdraw",
})
_VIRGIN_STATE_IGNORED_SEGMENTS = frozenset({
    "auth",
    "login",
    "log-in",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "session",
    "sessions",
    "refresh",
    "health",
    "healthz",
    "ready",
    "readyz",
    "livez",
})
_VIRGIN_STATIC_ASSET_EXTS = (".js", ".mjs", ".cjs", ".wasm", ".otf", ".avif", ".bmp")
_OWNER_FIELD_KEYS = (
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
_PRIMARY_ID_KEYS = ("id", "uuid")
_MAX_OBJECTS_PER_TEMPLATE = 6
_MAX_PARAM_VALUES_TRACKED = 6
_PLAIN_ALNUM_VAL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_NON_PROBE_PARAM_NAMES = frozenset({
    "page",
    "limit",
    "offset",
    "per_page",
    "page_size",
    "size",
    "cursor",
    "csrf",
    "csrf_token",
    "_csrf",
    "xsrf",
    "xsrf_token",
    "lang",
    "locale",
    "v",
    "_",
    "t",
    "ts",
    "timestamp",
})
_PROBE_PRIORITY_PARAM_NAMES = frozenset({
    "q",
    "query",
    "search",
    "term",
    "keyword",
    "filter",
    "sort",
    "order",
    "order_by",
    "sort_by",
    "dir",
    "direction",
    "next",
    "redirect",
    "return",
    "return_to",
    "redirect_uri",
    "url",
    "target",
    "continue",
    "callback",
    "goto",
    "dest",
    "destination",
    "path",
    "template",
    "view",
    "name",
    "message",
    "comment",
})
HIGH_RISK_PARAM_NAMES: frozenset[str] = frozenset({
    "id",
    "file",
    "filename",
    "path",
    "dir",
    "folder",
    "url",
    "uri",
    "next",
    "redirect",
    "return",
    "callback",
    "q",
    "query",
    "search",
    "sort",
    "order",
    "filter",
    "template",
    "view",
    "page",
    "cate",
    "cat",
    "cmd",
    "exec",
    "email",
    "username",
    "role",
    "admin",
    "token",
})
_HIGH_RISK_COMPOUND_PARAM_TOKENS: frozenset[str] = frozenset({
    "file",
    "filename",
    "filepath",
    "path",
    "folder",
    "url",
    "uri",
    "redirect",
    "return",
    "callback",
    "query",
    "search",
    "sort",
    "filter",
    "template",
    "cmd",
    "exec",
    "email",
    "username",
    "role",
    "admin",
    "token",
})
_HIGH_RISK_LOW_SIGNAL_META_PARAMS: frozenset[str] = _NON_PROBE_PARAM_NAMES - HIGH_RISK_PARAM_NAMES
_UPLOAD_ROUTE_TOKENS: frozenset[str] = frozenset({
    "upload",
    "uploads",
    "fileupload",
    "import",
    "attach",
    "attachment",
    "attachments",
})
_AUTH_ADMIN_ROUTE_TOKENS: frozenset[str] = frozenset({
    "admin",
    "login",
    "signin",
    "signup",
    "register",
    "auth",
    "password",
    "passwd",
    "reset",
    "role",
    "roles",
    "permission",
    "permissions",
})
_LOGOUT_OR_DESTRUCTIVE_SEGMENTS: frozenset[str] = frozenset({
    "logout",
    "log-out",
    "log_out",
    "signout",
    "sign-out",
    "sign_out",
    "reboot",
    "restart",
    "shutdown",
    "shut-down",
    "shut_down",
    "poweroff",
    "power-off",
    "power_off",
    "factory-reset",
    "factory_reset",
})
_MUTATING_HTTP_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_HIGH_RISK_SCORE_THRESHOLD = 25
_ROUTE_FAMILY_PREFIX_RE = re.compile(
    r"^(?:api|ajax[-_]?api|rest|rpc|v\d+(?:\.\d+)?|\d+\.\d+)$",
    re.IGNORECASE,
)
_ROUTE_API_PATH_RE = re.compile(
    r"^/(?:api|ajax[-_]?api|rest|rpc|v\d+(?:\.\d+)?|graphql)(?:/|$)|/graphql(?:/|$)",
    re.IGNORECASE,
)
_BENIGN_QUERY_VAL_RE = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?$")
_BENIGN_EMAIL_VAL_RE = re.compile(r"^[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
_API_PREFIX_RE = re.compile(r"^/(api(?:/v\d+)?|v\d+)(?=/|$)", re.IGNORECASE)
_NUMERIC_SLUG_CATEGORY_RE = re.compile(r"^\d+-[a-z]", re.IGNORECASE)
_PRESERVED_CATALOG_PLACEHOLDERS = frozenset({
    "{catalog_category}",
    "{catalog_product}",
    "{catalog_campaign}",
    "{catalog_brand}",
})
_CATALOG_BRAND_PREFIX_SEGMENTS = frozenset({
    "marka",
    "markalar",
    "brand",
    "brands",
    "magaza",
    "magazalar",
})
_CATALOG_CAMPAIGN_PARENT_SEGMENTS = frozenset({
    "firsat",
    "firsatlar",
    "kampanya",
    "kampanyalar",
    "campaigns",
    "deals",
    "offers",
    "indirim",
    "indirimler",
})
_CATALOG_PRODUCT_PARENT_SEGMENTS = frozenset({
    "product",
    "products",
    "urun",
    "urunler",
})
_CATALOG_CONTAINER_SEGMENTS = frozenset({
    *_CATALOG_BRAND_PREFIX_SEGMENTS,
    *_CATALOG_CAMPAIGN_PARENT_SEGMENTS,
    *_CATALOG_PRODUCT_PARENT_SEGMENTS,
    "kategori",
    "kategoriler",
    "category",
    "categories",
    "catalog",
    "katalog",
    "collection",
    "collections",
    "store",
    "shop",
    "p",
    "c",
    "k",
    "b",
    "m",
    "s",
})
_FUNCTIONAL_ROOT_SEGMENTS = frozenset({
    "api",
    "ajax",
    "ajax-api",
    "rest",
    "rpc",
    "graphql",
    "gql",
    "auth",
    "oauth",
    "oauth2",
    "sso",
    "login",
    "log-in",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "logout",
    "log-out",
    "signout",
    "sign-out",
    "session",
    "sessions",
    "token",
    "refresh-token",
    "refresh",
    "password",
    "forgot-password",
    "reset-password",
    "admin",
    "administrator",
    "manage",
    "management",
    "dashboard",
    "panel",
    "console",
    "internal",
    "debug",
    "metrics",
    "health",
    "healthz",
    "ready",
    "readyz",
    "livez",
    "status",
    "account",
    "accounts",
    "profile",
    "profiles",
    "settings",
    "user",
    "users",
    "member",
    "members",
    "hesabim",
    "uyelik",
    "uye",
    "profil",
    "ayarlar",
    "adreslerim",
    "siparislerim",
    "favorilerim",
    "puanlarim",
    "kuponlarim",
    "mesajlarim",
    "bildirimlerim",
    "iade",
    "iadelerim",
    "cart",
    "sepet",
    "sepetim",
    "basket",
    "checkout",
    "odeme",
    "payment",
    "payments",
    "pay",
    "order",
    "orders",
    "invoice",
    "invoices",
    "ticket",
    "tickets",
    "billing",
    "subscription",
    "subscriptions",
    "wallet",
    "cuzdan",
    "search",
    "arama",
    "ara",
    "upload",
    "uploads",
    "download",
    "downloads",
    "export",
    "import",
    "webhook",
    "webhooks",
    "callback",
    "redirect",
    "proxy",
    "fetch",
    "render",
    "portal",
    "sys",
    "system",
    "static",
    "assets",
    "public",
    "media",
    "files",
    "images",
    "docs",
    "help",
    "support",
    "contact",
    "about",
    "faq",
    "error",
    "errors",
    "promo",
    "promos",
    "coupon",
    "coupons",
    "voucher",
    "vouchers",
})
_CATALOG_EXCLUDED_SECURITY_TOKENS = frozenset({
    "api",
    "auth",
    "oauth",
    "oauth2",
    "sso",
    "login",
    "signin",
    "signup",
    "logout",
    "signout",
    "register",
    "password",
    "passwd",
    "token",
    "jwt",
    "csrf",
    "xsrf",
    "session",
    "admin",
    "administrator",
    "webhook",
    "callback",
    "redirect",
    "proxy",
    "upload",
    "download",
    "export",
    "import",
    "exec",
    "eval",
    "debug",
    "diagnostics",
    "diagnostic",
    "health",
    "healthz",
    "readyz",
    "metrics",
    "swagger",
    "openapi",
    "graphql",
    "checkout",
    "billing",
    "invoice",
    "hesabim",
    "sepetim",
    "puanlarim",
    "siparislerim",
    "payment",
    "payments",
    "permission",
    "permissions",
    "role",
    "roles",
    "audit",
    "config",
    "settings",
    "account",
    "accounts",
    "users",
    "user",
    "verify",
    "verification",
    "reset",
})
_CATALOG_SAFE_SLUG_SEG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_CATALOG_K_CODE_RE = re.compile(r"^[a-z0-9]{2,}(?:-[a-z0-9]+)*-k-([a-z0-9]{3,})$")
_CATALOG_CAT_CODE_RE = re.compile(r"^[a-z0-9]{2,}(?:-[a-z0-9]+)*-(?:c|cat)-([a-z0-9]{2,})$")
_CATALOG_XC_CODE_RE = re.compile(r"^[a-z0-9]{2,}(?:-[a-z0-9]+)*-x-[cb]\d{2,}$")
_CATALOG_PROD_CODE_RE = re.compile(r"^[a-z0-9]{2,}(?:-[a-z0-9]+)*-(?:p|i)-([a-z0-9]{3,})$")
_VOWELS = frozenset("aeiou")
_MAX_CATALOG_DISCOVERED_PER_TEMPLATE = 5
_MAX_SPA_FP_BUCKETS = 64
_MAX_SPA_FP_PATHS_PER_BUCKET = 32
_SPA_404_MIN_BYTES = 512
_SPA_SHELL_MIN_BYTES = 1024
_NON_RESOURCE_UI_SEGMENTS = frozenset({
    "login",
    "logout",
    "log-in",
    "log-out",
    "signin",
    "sign-in",
    "signout",
    "sign-out",
    "signup",
    "sign-up",
    "register",
    "auth",
    "oauth",
    "oauth2",
    "sso",
    "session",
    "refresh",
    "forgot-password",
    "reset-password",
    "static",
    "assets",
    "public",
    "media",
    "img",
    "images",
    "css",
    "js",
    "fonts",
    "favicon.ico",
    "robots.txt",
    "sitemap.xml",
    "health",
    "healthz",
    "ready",
    "readyz",
    "livez",
    "metrics",
    "status",
    "dashboard",
    "home",
    "index",
    "docs",
    "openapi.json",
    "swagger",
    "swagger-ui",
    "redoc",
    "api-docs",
    "admin",
    "search",
    "settings",
    "profile",
    "account",
    "help",
    "about",
    "contact",
    "error",
    "errors",
})
_NON_RESOURCE_FILE_EXTS = (
    ".js",
    ".mjs",
    ".css",
    ".html",
    ".htm",
    ".json",
    ".xml",
    ".txt",
    ".ico",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
)
# Body template and validation schema limits
_MAX_BODY_TEMPLATES = 40
_MAX_BODY_TEMPLATE_CHARS = 600
_MAX_BODY_TEMPLATE_STR_LEN = 64
_MAX_BODY_TEMPLATE_LIST_LEN = 4
_MAX_BODY_TEMPLATE_DICT_KEYS = 16
_MAX_BODY_TEMPLATE_DEPTH = 4
_MAX_SCHEMA_HINTS_PER_TEMPLATE = 24
_MAX_SCHEMA_HINT_TEMPLATES = 60
_MAX_PARAMS_PER_TEMPLATE = 32
_MAX_PATH_PARAMS_PER_ROUTE = 6
_MAX_ERROR_DELTA_PARAMS = 40
_MAX_ERROR_DELTA_VALUE_TRACKED = 120
_ROTATING_META_PARAMS: frozenset[str] = frozenset({
    "csrf",
    "csrf_token",
    "_csrf",
    "xsrf",
    "xsrf_token",
    "_",
    "ts",
    "timestamp",
})
_SPA_ONLY_SOURCE_TAGS: frozenset[str] = frozenset({"spa-route", "spa-hash"})
_SPA_CRAWL_SOURCE_TAGS: frozenset[str] = frozenset({"spa-route", "spa-hash", "crawl"})

_SECRET_KEY_SUBSTRINGS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "accesskey",
    "passphrase",
    "cookie",
    "jwt",
    "bearer",
)
_SECRET_KEY_EXACT_TOKENS = frozenset({
    "pwd",
    "auth",
    "authorization",
    "csrf",
    "xsrf",
    "session_id",
    "sessionid",
    "sid",
    "otp",
    "pin",
})
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

_VALIDATION_FIELD_SEG_RE = re.compile(r"^[A-Za-z0-9_$-]{1,48}$")
_VALIDATION_TYPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,48}$")
_VALIDATION_ROOT_SCOPES = frozenset({"body", "query", "path", "header", "cookie"})
_NON_TYPE_LABELS = frozenset({"field", "error", "validation_error", "invalid"})
_SAFE_MULTIPART_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]$]{1,64}$")
_METHOD_URL_KEY_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$",
    re.IGNORECASE,
)


def _sanitize_multipart_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name or not _SAFE_MULTIPART_NAME_RE.fullmatch(name):
        return ""
    return name

_PATH_KV_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_URL_SCHEME_VAL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{0,15}:$")
_MALFORMED_PATH_CHARS = frozenset(('"', "'", "`", "\\", "(", ")", ",", ";", "*"))
_PATH_TEMPLATE_PARAM_RE = re.compile(r"^\{([A-Za-z][A-Za-z0-9_.-]{0,31})(?::([A-Za-z0-9_-]{1,16}))?\}$")
_PLAIN_PATH_VAL_RE = re.compile(
    r"^(?:[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?|https?://[A-Za-z0-9._:/-]+)$"
)
_PATH_INPUT_PARAM_TOKENS = frozenset({
    "file",
    "filename",
    "filepath",
    "path",
    "pathname",
    "dir",
    "directory",
    "folder",
    "url",
    "uri",
    "href",
    "redirect",
    "dest",
    "destination",
    "target",
    "goto",
    "callback",
    "proxy",
    "forward",
    "upstream",
    "template",
    "tpl",
    "include",
    "src",
    "source",
    "next",
    "return",
    "location",
})
_PATH_INPUT_PARENT_SEGMENTS = frozenset({
    "download",
    "downloads",
    "fetch",
    "proxy",
    "redirect",
    "redir",
    "forward",
    "goto",
    "render",
    "template",
    "templates",
    "include",
    "serve",
    "readfile",
    "getfile",
    "sendfile",
    "file",
    "fetch-url",
    "fetch_url",
})


def _is_secret_key(key: str) -> bool:
    """Return True if a JSON key name looks like a credential, token, or secret."""
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", str(key or "")).strip().lower()
    if not snake:
        return False
    norm = snake.replace("-", "_")
    if any(sub in norm for sub in _SECRET_KEY_SUBSTRINGS):
        return True
    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(norm) if tok]
    if norm in _SECRET_KEY_EXACT_TOKENS or any(tok in _SECRET_KEY_EXACT_TOKENS for tok in tokens):
        return True
    return False


def _sanitize_json_template(
    obj: Any,
    *,
    depth: int = 0,
    max_str_len: int = _MAX_BODY_TEMPLATE_STR_LEN,
    max_list_len: int = _MAX_BODY_TEMPLATE_LIST_LEN,
    max_dict_keys: int = _MAX_BODY_TEMPLATE_DICT_KEYS,
) -> Any:
    """Compact and secret-redact a JSON structure for safe schema-template reuse."""
    if isinstance(obj, dict):
        if depth >= _MAX_BODY_TEMPLATE_DEPTH:
            return {}
        out: dict[str, Any] = {}
        for k, v in list(obj.items())[:max_dict_keys]:
            k_str = str(k)[:64]
            if not k_str:
                continue
            if _is_secret_key(k_str):
                out[k_str] = "<redacted>"
            else:
                out[k_str] = _sanitize_json_template(
                    v,
                    depth=depth + 1,
                    max_str_len=max_str_len,
                    max_list_len=max_list_len,
                    max_dict_keys=max_dict_keys,
                )
        return out
    if isinstance(obj, list):
        if depth >= _MAX_BODY_TEMPLATE_DEPTH:
            return []
        return [
            _sanitize_json_template(
                item,
                depth=depth + 1,
                max_str_len=max_str_len,
                max_list_len=max_list_len,
                max_dict_keys=max_dict_keys,
            )
            for item in obj[:max_list_len]
        ]
    if isinstance(obj, str):
        low = obj.lower()
        if "<redacted" in low or (low.strip().startswith("bearer ") and len(obj.strip()) > 12):
            return "<redacted>"
        if len(obj) > max_str_len:
            if max_str_len <= 3:
                return obj[:max_str_len]
            return obj[: max_str_len - 3] + "..."
        return obj
    if isinstance(obj, bool) or obj is None or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else 0.0
    text = str(obj)
    return text[:max_str_len]


def _serialized_json_len(doc: Any) -> int:
    return len(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))


def _fit_body_template_budget(
    doc: dict[str, Any],
    *,
    max_chars: int = _MAX_BODY_TEMPLATE_CHARS,
) -> dict[str, Any]:
    """Ensure a sanitized JSON template dict serializes compactly within `max_chars`."""
    if _serialized_json_len(doc) <= max_chars:
        return doc
    for str_len, list_len in ((24, 2), (12, 1), (8, 1)):
        shrunk = _sanitize_json_template(
            doc,
            max_str_len=str_len,
            max_list_len=list_len,
            max_dict_keys=_MAX_BODY_TEMPLATE_DICT_KEYS,
        )
        if isinstance(shrunk, dict) and _serialized_json_len(shrunk) <= max_chars:
            return shrunk
        if isinstance(shrunk, dict):
            doc = shrunk

    kept: dict[str, Any] = {}
    for k, v in doc.items():
        candidate = dict(kept)
        candidate[k] = v
        if _serialized_json_len(candidate) <= max_chars:
            kept = candidate
            continue
        fallback_val: Any = [] if isinstance(v, list) else ({} if isinstance(v, dict) else "...")
        candidate[k] = fallback_val
        if _serialized_json_len(candidate) <= max_chars:
            kept = candidate
    return kept


def _normalize_validation_path(
    raw_path: Any,
    *,
    location: str = "",
    method: str = "POST",
) -> tuple[str, str] | None:
    """Normalize a validation error field path into `(dotted_path, leaf_param)`."""
    parts: list[str]
    if isinstance(raw_path, (list, tuple)):
        parts = [str(p).strip() for p in raw_path if str(p).strip() != ""]
    elif isinstance(raw_path, str):
        text = raw_path.strip()
        if not text:
            return None
        if "/" in text:
            parts = [seg.strip() for seg in text.strip("/").split("/") if seg.strip()]
        else:
            parts = [seg.strip() for seg in text.split(".") if seg.strip()]
    else:
        return None

    if not parts:
        return None
    parts = parts[:8]
    if any(not _VALIDATION_FIELD_SEG_RE.fullmatch(seg) for seg in parts):
        return None

    loc_low = str(location or "").strip().lower()
    if loc_low in _VALIDATION_ROOT_SCOPES and parts[0].lower() not in _VALIDATION_ROOT_SCOPES:
        parts = [loc_low, *parts]
    elif parts[0].lower() not in _VALIDATION_ROOT_SCOPES and method in {"POST", "PUT", "PATCH"}:
        parts = ["body", *parts]

    formatted_path = ".".join(parts)
    leaf = ""
    for seg in reversed(parts):
        if not seg.isdigit() and seg.lower() not in _VALIDATION_ROOT_SCOPES and not seg.startswith("$"):
            leaf = seg
            break
    return formatted_path, leaf


def _extract_validation_schema_hints(
    parsed: Any,
    *,
    method: str = "POST",
) -> tuple[list[str], list[str]]:
    """Extract compact validation field hints (`body.data:list_type`) and leaf param names from 400/422 JSON."""
    hints: list[str] = []
    leaves: list[str] = []
    seen_hints: set[str] = set()
    seen_leaves: set[str] = set()

    def _add(fpath: str, leaf: str, err_type: str = "") -> None:
        clean_type = str(err_type or "").strip()
        if clean_type.lower() in _NON_TYPE_LABELS or not _VALIDATION_TYPE_RE.fullmatch(clean_type):
            clean_type = ""
        hint = f"{fpath}:{clean_type}" if clean_type else fpath
        if hint not in seen_hints and len(hints) < _MAX_SCHEMA_HINTS_PER_TEMPLATE:
            seen_hints.add(hint)
            hints.append(hint)
        if leaf and leaf not in seen_leaves and len(leaves) < _MAX_SCHEMA_HINTS_PER_TEMPLATE:
            seen_leaves.add(leaf)
            leaves.append(leaf)

    def _extract_item(item: dict[str, Any]) -> None:
        location = str(item.get("location") or item.get("in") or "").strip().lower()
        raw_path: Any = None
        for key in ("loc", "path", "field", "param", "property", "missing_field", "instancePath", "dataPath", "name", "key"):
            cand = item.get(key)
            if cand is not None and cand != "" and cand != []:
                raw_path = cand
                break
        # Support AJV-style `{instancePath: "/items/0", params: {missingProperty: "name"}}`
        params_obj = item.get("params")
        if isinstance(params_obj, dict):
            missing_prop = params_obj.get("missingProperty")
            if isinstance(missing_prop, str) and missing_prop.strip():
                if isinstance(raw_path, str) and raw_path.strip():
                    raw_path = f"{raw_path.rstrip('/')}/{missing_prop.strip()}"
                elif raw_path is None:
                    raw_path = missing_prop.strip()

        norm = _normalize_validation_path(raw_path, location=location, method=method)
        if norm is None:
            return
        fpath, leaf = norm

        err_type = ""
        for tkey in ("expected", "expected_type", "expectedType", "type", "code"):
            raw_t = item.get(tkey)
            if isinstance(raw_t, str) and raw_t.strip():
                cand_t = raw_t.strip()
                if cand_t.lower() not in _NON_TYPE_LABELS and _VALIDATION_TYPE_RE.fullmatch(cand_t):
                    err_type = cand_t
                    break
        _add(fpath, leaf, err_type)

    if isinstance(parsed, list):
        for elem in parsed[:30]:
            if isinstance(elem, dict) and any(
                k in elem for k in ("loc", "path", "field", "param", "instancePath", "dataPath")
            ):
                _extract_item(elem)
        return hints, leaves

    if not isinstance(parsed, dict):
        return hints, leaves

    matched_container = False
    for key in ("detail", "errors", "issues", "violations", "validation_errors", "validationErrors"):
        val = parsed.get(key)
        if isinstance(val, list):
            matched_container = True
            for elem in val[:30]:
                if isinstance(elem, dict):
                    _extract_item(elem)
                elif isinstance(elem, str) and _VALIDATION_FIELD_SEG_RE.fullmatch(elem.strip()):
                    norm = _normalize_validation_path(elem.strip(), method=method)
                    if norm is not None:
                        _add(norm[0], norm[1])
        elif isinstance(val, dict):
            matched_container = True
            if any(k in val for k in ("loc", "path", "field", "param", "instancePath")):
                _extract_item(val)
            else:
                for fk in list(val.keys())[:24]:
                    fk_s = str(fk or "").strip()
                    if fk_s.lower() in {"message", "error", "code", "status", "detail"}:
                        continue
                    norm = _normalize_validation_path(fk_s, method=method)
                    if norm is not None:
                        _add(norm[0], norm[1])

    for key in ("fieldErrors", "field_errors", "fields"):
        val = parsed.get(key)
        if isinstance(val, dict):
            matched_container = True
            for fk in list(val.keys())[:24]:
                norm = _normalize_validation_path(str(fk or "").strip(), method=method)
                if norm is not None:
                    _add(norm[0], norm[1])
        elif isinstance(val, list):
            matched_container = True
            for elem in val[:24]:
                if isinstance(elem, dict):
                    _extract_item(elem)
                elif isinstance(elem, str):
                    norm = _normalize_validation_path(elem.strip(), method=method)
                    if norm is not None:
                        _add(norm[0], norm[1])

    for key in ("missing", "missing_fields", "missingFields", "required", "required_fields", "requiredFields"):
        val = parsed.get(key)
        if isinstance(val, list):
            matched_container = True
            for elem in val[:24]:
                if isinstance(elem, str) and elem.strip():
                    norm = _normalize_validation_path(elem.strip(), method=method)
                    if norm is not None:
                        _add(norm[0], norm[1])
        elif isinstance(val, str) and _VALIDATION_FIELD_SEG_RE.fullmatch(val.strip()):
            matched_container = True
            norm = _normalize_validation_path(val.strip(), method=method)
            if norm is not None:
                _add(norm[0], norm[1])

    if not matched_container and any(k in parsed for k in ("loc", "path", "field", "param", "missing_field")):
        _extract_item(parsed)

    return hints, leaves


def _split_path_kv_segment(seg: str) -> tuple[str, str] | None:
    """Return `(key_lower, value)` if `seg` is a valid path-embedded `key=value` segment."""
    if "=" not in seg or seg.endswith("=="):
        return None
    key, _, val = seg.partition("=")
    if not key or not _PATH_KV_KEY_RE.fullmatch(key):
        return None
    if val.startswith("="):
        return None
    key_low = key.lower()
    if not val and not (
        key_low in _PATH_INPUT_PARAM_TOKENS
        or key_low in {"id", "q"}
        or (key.islower() and key.isalpha() and 3 <= len(key) <= 20)
    ):
        return None
    return key_low, val


def _extract_path_embedded_param_pairs(path: str) -> list[tuple[str, str]]:
    """Extract `(marker, observed_value)` for path-embedded `key=value` and file/url/redirect `{param}` segments."""
    raw = str(path or "").strip()
    if not raw or is_malformed_url_path(raw):
        return []
    norm_p = normalize_path(raw)
    raw_segs = [seg for seg in norm_p.split("/") if seg]
    if not raw_segs:
        return []

    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    for idx, seg in enumerate(raw_segs):
        if len(out) >= _MAX_PATH_PARAMS_PER_ROUTE:
            break
        kv = _split_path_kv_segment(seg)
        if kv is not None:
            key_low, val = kv
            marker = f"path:{key_low}="
            raw_key = seg.partition("=")[0]
            consumes_tail = (
                (_URL_SCHEME_VAL_RE.fullmatch(val) is not None)
                or (key_low in _PATH_INPUT_PARAM_TOKENS and val in {"", ".", ".."})
            )
            full_val = val
            if consumes_tail and idx + 1 < len(raw_segs):
                prefix_segs = "/" + "/".join(raw_segs[:idx]) if idx > 0 else ""
                needle = f"{prefix_segs}/{raw_key}="
                pos = norm_p.find(needle)
                if pos != -1:
                    full_val = norm_p[pos + len(needle) :]
                else:
                    full_val = "/".join([val, *raw_segs[idx + 1 :]])
            if marker not in seen:
                seen.add(marker)
                out.append((marker, full_val[:64]))
            if consumes_tail:
                break
            continue

        tmpl_match = _PATH_TEMPLATE_PARAM_RE.fullmatch(seg)
        if tmpl_match is not None:
            param_name = tmpl_match.group(1)
            converter = (tmpl_match.group(2) or "").lower()
            param_low = param_name.lower()
            param_tokens = [tok for tok in _TOKEN_SPLIT_RE.split(param_low) if tok]
            prev_seg = raw_segs[idx - 1].lower() if idx > 0 else ""
            matches_param = (
                converter == "path"
                or param_low in _PATH_INPUT_PARAM_TOKENS
                or any(tok in _PATH_INPUT_PARAM_TOKENS for tok in param_tokens)
            )
            is_generic_id = param_low == "id" or param_low.endswith(("_id", "-id"))
            matches_parent = (prev_seg in _PATH_INPUT_PARENT_SEGMENTS) and not is_generic_id
            if matches_param or matches_parent:
                marker = f"path:{param_low}"
                if marker not in seen:
                    seen.add(marker)
                    out.append((marker, ""))

    return out


def _extract_path_embedded_params(path: str) -> list[str]:
    """Extract `path:...` input-parameter markers from path-embedded `key=value` or `{param}` segments."""
    return [marker for marker, _ in _extract_path_embedded_param_pairs(path)]


def is_malformed_url_path(url_or_path: str) -> bool:
    """Return True if a URL/path contains malformed path fragments.

    Rejects backslashes, quotes, JS template-literal syntax (`${`), JS/regex code
    punctuation (`(`, `)`, `,`, `;`, `*`), consecutive slashes (`//`) in the path,
    path whitespace, and control characters while preserving valid OpenAPI/route
    templates like `{id}`, path-embedded URL inputs, and query/fragment values.
    """
    raw_in = str(url_or_path or "")
    raw = raw_in.strip(" ")
    if not raw:
        return False
    # Inspect raw input before urlsplit, which strips ASCII \t, \r, \n per WHATWG.
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return True
    raw_no_qf = raw.split("#", 1)[0].split("?", 1)[0]
    if "\\" in raw_no_qf:
        return True
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return True
    if not parsed.scheme and (raw_no_qf == "//" or raw_no_qf.startswith("///")):
        path = raw_no_qf
    else:
        path = parsed.path or ""
    if not path:
        return False
    if has_double_slash_path(path) or "\\" in path or "${" in path:
        return True
    if any(ch in _MALFORMED_PATH_CHARS for ch in path):
        return True
    if any(ch.isspace() for ch in path):
        return True
    return False


def is_non_endpoint_source_path(url_or_path: str) -> bool:
    """Return True for frontend source/bundler artifact URLs, schema pointers, or malformed path fragments.

    Preserves `.js` bundle URLs (e.g. `/assets/app.js`), legitimate API/OpenAPI/GraphQL
    routes, and valid `{id}` route templates.
    """
    if is_malformed_url_path(url_or_path):
        return True
    return is_non_endpoint_noise_path(url_or_path)


def _extract_api_prefix(path: str) -> str:
    """Return normalized observed API prefix (e.g. `/api/v1`, `/api`, `/v1`) or empty string."""
    norm_p = normalize_path(path)
    match = _API_PREFIX_RE.match(norm_p)
    if not match:
        return ""
    return f"/{match.group(1).lower()}"


def _is_non_resource_api_subpath(api_prefix: str, path: str) -> bool:
    """Return True if an API path under `api_prefix` only targets utility/auth/docs subpaths."""
    norm_p = normalize_path(path).lower()
    if norm_p == api_prefix:
        return True
    remainder = norm_p[len(api_prefix):].lstrip("/")
    if not remainder:
        return True
    first_sub = remainder.split("/", 1)[0]
    return first_sub in _NON_RESOURCE_UI_SEGMENTS or _is_auth_utility_path(norm_p)


def _classify_catalog_slug_segment(seg: str, *, parent_seg: str = "") -> str | None:
    """Classify an e-commerce/CMS SEO catalog slug segment into `'category'`, `'product'`, `'campaign'`, or `None`."""
    raw = str(seg or "").strip()
    if not raw or not _CATALOG_SAFE_SLUG_SEG_RE.fullmatch(raw):
        return None
    low = raw.lower()
    if low in _FUNCTIONAL_ROOT_SEGMENTS or low in _NON_RESOURCE_UI_SEGMENTS:
        return None
    if low.isdigit() or _UUID_SEG_RE.fullmatch(low) or _HEX_ID_SEG_RE.fullmatch(low):
        return None

    m_k = _CATALOG_K_CODE_RE.fullmatch(low)
    if m_k is not None:
        code = m_k.group(1)
        raw_code = raw.rsplit("-", 1)[-1]
        if (
            any(ch.isdigit() for ch in code)
            or (len(code) >= 4 and not any(ch in _VOWELS for ch in code))
            or any(ch.isupper() for ch in raw_code)
        ):
            return "category"

    m_cat = _CATALOG_CAT_CODE_RE.fullmatch(low)
    if m_cat is not None:
        code = m_cat.group(1)
        is_cat_tag = f"-cat-{code}" in low
        if (
            (any(ch.isdigit() for ch in code) and (len(code) >= 3 or is_cat_tag))
            or (is_cat_tag and len(code) >= 4 and not any(ch in _VOWELS for ch in code))
        ):
            return "category"

    if _CATALOG_XC_CODE_RE.fullmatch(low):
        return "category"

    m_prod = _CATALOG_PROD_CODE_RE.fullmatch(low)
    if m_prod is not None:
        code = m_prod.group(1)
        if any(ch.isdigit() for ch in code) or (
            len(code) >= 4 and not any(ch in _VOWELS for ch in code)
        ):
            return "product"

    parent_low = str(parent_seg or "").strip().lower()
    tokens = {tok for tok in low.split("-") if tok}
    if parent_low in _CATALOG_CAMPAIGN_PARENT_SEGMENTS:
        if low.startswith("l-") and len(low) >= 6 and (
            "-" in low[2:] or (low[2:].isalnum() and low[2:] not in _FUNCTIONAL_ROOT_SEGMENTS)
        ):
            return "campaign"
        if low.count("-") >= 1 and len(low) >= 10 and not (tokens & _CATALOG_EXCLUDED_SECURITY_TOKENS):
            return "campaign"

    if (
        parent_low in _CATALOG_PRODUCT_PARENT_SEGMENTS
        and low.count("-") >= 2
        and len(low) >= 15
        and not (tokens & _CATALOG_EXCLUDED_SECURITY_TOKENS)
    ):
        return "product"

    if (
        low.count("-") >= 4
        and len(low) >= 35
        and not (tokens & _CATALOG_EXCLUDED_SECURITY_TOKENS)
    ):
        return "product"

    return None


def is_catalog_route(url_or_path: str) -> bool:
    """Return True when `url_or_path` is a non-API storefront/SEO catalog or campaign route."""
    raw = str(url_or_path or "").strip()
    if not raw or is_non_endpoint_source_path(raw):
        return False
    norm_p = normalize_path(raw)
    if norm_p == "/" or _ROUTE_API_PATH_RE.search(norm_p):
        return False
    raw_segs = [seg for seg in norm_p.split("/") if seg]
    if not raw_segs:
        return False
    if raw_segs[0].lower() in _FUNCTIONAL_ROOT_SEGMENTS:
        return False
    tmpl = route_template_of(norm_p)
    if any(ph in tmpl for ph in _PRESERVED_CATALOG_PLACEHOLDERS):
        return True
    if raw_segs[0].lower() == "catalog" and not any(
        tok in _CATALOG_EXCLUDED_SECURITY_TOKENS
        for seg in raw_segs[1:]
        for tok in _TOKEN_SPLIT_RE.split(seg.lower())
        if tok
    ):
        return True
    return False


def _extract_ui_resource_info(path: str) -> tuple[str, bool, str] | None:
    """Extract `(resource, is_collection, concrete_id)` from a non-API UI route, or None."""
    if is_non_endpoint_source_path(path) or _is_passive_spec_path(path):
        return None
    norm_p = normalize_path(path)
    if (
        norm_p == "/"
        or _extract_api_prefix(norm_p)
        or is_static_asset_url(norm_p)
        or is_non_endpoint_source_path(norm_p)
        or is_catalog_route(norm_p)
    ):
        return None
    if norm_p.lower().endswith(_NON_RESOURCE_FILE_EXTS):
        return None
    segs = [seg for seg in norm_p.split("/") if seg]
    if not segs:
        return None
    resource = segs[0].lower()
    if (
        resource in _NON_RESOURCE_UI_SEGMENTS
        or resource.startswith((".", "_", "$"))
        or "=" in resource
        or is_id_segment(resource)
        or _NUMERIC_SLUG_CATEGORY_RE.match(resource) is not None
        or resource.endswith(_NON_RESOURCE_FILE_EXTS)
    ):
        return None
    if len(segs) == 1:
        return (resource, True, "")
    second = segs[1]
    if is_id_segment(second) and "{" not in second:
        return (resource, False, second)
    return (resource, False, "")


def is_id_segment(seg: str) -> bool:
    """Return True if a URL path segment looks like a concrete resource ID or `{id}` placeholder."""
    low = str(seg or "").strip().lower()
    if not low:
        return False
    if _classify_catalog_slug_segment(seg) is not None:
        return False
    return bool(
        low.isdigit()
        or _UUID_SEG_RE.fullmatch(low)
        or _HEX_ID_SEG_RE.fullmatch(low)
        or _PREFIXED_ID_SEG_RE.fullmatch(low)
        or _TEMPLATE_SEG_RE.fullmatch(low)
    )


def normalize_path(url_or_path: str) -> str:
    """Return normalized lowercase path without trailing slash (except `/`)."""
    parsed = urlsplit(str(url_or_path or "").strip())
    path = (parsed.path or "/").strip()
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def route_template_of(url_or_path: str) -> str:
    """Normalize concrete resource ID, `key=value`, and SEO/catalog slug segments into route templates."""
    path = normalize_path(url_or_path)
    if path == "/":
        return "/"
    raw_segs = [seg for seg in path.split("/") if seg]
    if not raw_segs:
        return "/"
    low_segs = [seg.lower() for seg in raw_segs]
    allow_catalog_compression = (
        not _ROUTE_API_PATH_RE.search(path)
        and low_segs[0] not in _FUNCTIONAL_ROOT_SEGMENTS
        and not is_non_endpoint_source_path(path)
    )

    segments: list[str] = []
    kv_truncated = False
    for idx, seg in enumerate(raw_segs):
        seg_low = seg.lower()
        if seg_low in _PRESERVED_CATALOG_PLACEHOLDERS:
            segments.append(seg_low)
            continue
        kv = _split_path_kv_segment(seg)
        if kv is not None:
            key_low, val = kv
            segments.append(f"{key_low}={{val}}")
            if _URL_SCHEME_VAL_RE.fullmatch(val) or (
                key_low in _PATH_INPUT_PARAM_TOKENS and val in {"", ".", ".."}
            ):
                kv_truncated = True
                break
        elif allow_catalog_compression:
            parent_seg = raw_segs[idx - 1] if idx > 0 else ""
            cat_kind = _classify_catalog_slug_segment(seg, parent_seg=parent_seg)
            if cat_kind == "category":
                segments.append("{catalog_category}")
            elif cat_kind == "product":
                segments.append("{catalog_product}")
            elif cat_kind == "campaign":
                segments.append("{catalog_campaign}")
            elif is_id_segment(seg):
                segments.append("{id}")
            else:
                segments.append(seg_low)
        elif is_id_segment(seg):
            segments.append("{id}")
        else:
            segments.append(seg_low)

    if allow_catalog_compression and not kv_truncated and len(segments) >= 2:
        if (
            segments[0] in _CATALOG_BRAND_PREFIX_SEGMENTS
            and segments[1] not in _PRESERVED_CATALOG_PLACEHOLDERS
            and not segments[1].startswith("{")
            and segments[1] not in _FUNCTIONAL_ROOT_SEGMENTS
            and segments[1] not in {"all", "list", "search", "index", "new"}
            and "." not in segments[1]
            and "=" not in segments[1]
        ):
            segments[1] = "{catalog_brand}"

        for idx, seg_norm in enumerate(segments):
            if idx >= 1 and seg_norm in {"{catalog_category}", "{catalog_product}"}:
                for j in range(idx):
                    cand = segments[j]
                    if (
                        cand not in _CATALOG_CONTAINER_SEGMENTS
                        and cand not in _FUNCTIONAL_ROOT_SEGMENTS
                        and cand not in _PRESERVED_CATALOG_PLACEHOLDERS
                        and (cand == "{id}" or not cand.startswith("{"))
                        and "." not in cand
                        and "=" not in cand
                    ):
                        segments[j] = "{catalog_brand}"

    return "/" + "/".join(segments)


_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_SINGLE_LABEL_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_HEX_INT_HOST_RE = re.compile(r"^0x[0-9a-f]+$")
_CANONICAL_SCRIPT_STYLE_RE = re.compile(
    r"<(?:script|style)\b[^>]*>[\s\S]*?</(?:script|style)>",
    re.IGNORECASE,
)
_CANONICAL_TAG_RE = re.compile(r"<(link|base|a|form)\b([^>]*)>", re.IGNORECASE)
_CANONICAL_ATTR_RE = re.compile(
    r"""([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"""
)
_OPENAPI_SPEC_SUFFIXES: tuple[str, ...] = (
    "/swagger/v1/swagger.json",
    "/v3/api-docs",
    "/v2/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
)
_PASSIVE_SPEC_EXACT_SUFFIXES: tuple[str, ...] = (
    *_OPENAPI_SPEC_SUFFIXES,
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.yaml",
    "/swagger.yml",
    "/api-docs.json",
    "/swagger-ui",
    "/swagger-ui.html",
    "/redoc",
    "/swagger",
)


def _is_passive_spec_path(url_or_path: str) -> bool:
    """Return True for OpenAPI/Swagger specification or API-docs metadata probe paths."""
    norm_p = normalize_path(url_or_path).lower()
    if norm_p == "/":
        return False
    if norm_p.endswith(_PASSIVE_SPEC_EXACT_SUFFIXES):
        return True
    return "/api-docs/" in norm_p or "/swagger-ui/" in norm_p


def _is_spa_only_source(source_tag: str = "", sources: Sequence[str] = ()) -> bool:
    """Return True when a route was discovered strictly via client-side SPA routing tags."""
    tags: list[str] = []
    if source_tag:
        tags.append(str(source_tag).strip().lower())
    for src in sources:
        st = str(src or "").strip().lower()
        if st:
            tags.append(st)
    if not tags:
        return False
    return any(t in _SPA_ONLY_SOURCE_TAGS for t in tags) and all(
        t in _SPA_CRAWL_SOURCE_TAGS for t in tags
    )


def _is_soft_deny_200(
    receipt: dict[str, Any],
    *,
    method: str,
    status: int,
    body: str,
) -> bool:
    """Return True when HTTP 200 is an empty GET body or JSON access-denied envelope."""
    if status != 200:
        return False
    raw_len = receipt.get("response_length")
    has_zero_len = isinstance(raw_len, int) and not isinstance(raw_len, bool) and raw_len == 0
    if not has_zero_len and isinstance(raw_len, str) and raw_len.strip().isdigit():
        has_zero_len = int(raw_len.strip()) == 0
    if method == "GET" and len(body) == 0 and (raw_len is None or has_zero_len):
        return True
    stripped = body.lstrip()
    if stripped.startswith("{") and len(stripped) <= 2048:
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            code_raw = parsed.get("code")
            if isinstance(code_raw, int) and not isinstance(code_raw, bool):
                has_payload = any(
                    k in parsed and parsed[k] not in (None, "", [], {})
                    for k in ("result", "data", "rows", "items")
                )
                if not has_payload and (
                    code_raw in {401, 403}
                    or (code_raw == 400 and ("result" in parsed or "data" in parsed))
                ):
                    return True
    return False


def is_loopback_or_private_base_url(base_url: str) -> bool:
    """Return True strictly when ``base_url`` targets loopback or an RFC1918 private IP."""
    raw = str(base_url or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
        if ip.is_loopback:
            return True
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _RFC1918_NETWORKS)
    return False


def is_single_label_internal_host(host: str) -> bool:
    """Return True only for a single-label internal hostname (no dots, not localhost/IP)."""
    raw = str(host or "").strip().lower()
    if not raw or "." in raw or ":" in raw or "/" in raw:
        return False
    if raw == "localhost" or raw.isdigit() or _HEX_INT_HOST_RE.fullmatch(raw):
        return False
    if not _SINGLE_LABEL_HOST_RE.fullmatch(raw):
        return False
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return True
    return False


def _extract_single_label_url_host(raw_url: str) -> str:
    """Extract a validated single-label hostname from an http(s) or protocol-relative URL."""
    val = unescape(str(raw_url or "").strip())
    if not val:
        return ""
    if val.startswith("//"):
        if val.startswith("///"):
            return ""
        candidate = f"http:{val}"
    elif val.lower().startswith(("http://", "https://")):
        candidate = val
    else:
        return ""
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return ""
    if parsed.username is not None or parsed.password is not None:
        return ""
    host = (parsed.hostname or "").strip().lower()
    if is_single_label_internal_host(host):
        return host
    return ""


def detect_internal_canonical_hosts(
    html_text: str,
    *,
    base_url: str,
    location_header: str = "",
) -> set[str]:
    """Detect single-label internal canonical hostnames for loopback/RFC1918 targets only.

    Sources checked (strictly single-label hostnames, never dotted/external domains):
    1. ``<link rel="canonical" href="...">`` and ``<base href="...">``
    2. Same-app ``Location`` redirect header
    3. Dominant single-label host appearing in ``>= 3`` ``<a href>`` / ``<form action>`` tags
    """
    if not is_loopback_or_private_base_url(base_url):
        return set()
    base_host = (urlsplit(base_url).hostname or "").strip().lower()
    detected: set[str] = set()

    if location_header:
        loc_host = _extract_single_label_url_host(location_header)
        if loc_host and loc_host != base_host:
            detected.add(loc_host)

    text = str(html_text or "")
    if not text:
        return detected

    cleaned = _CANONICAL_SCRIPT_STYLE_RE.sub(" ", text)
    link_form_counts: dict[str, int] = {}

    for match in _CANONICAL_TAG_RE.finditer(cleaned):
        tag = match.group(1).lower()
        attrs_raw = match.group(2) or ""
        attrs: dict[str, str] = {}
        for attr_m in _CANONICAL_ATTR_RE.finditer(attrs_raw):
            aname = attr_m.group(1).lower()
            aval = attr_m.group(2) if attr_m.group(2) is not None else (
                attr_m.group(3) if attr_m.group(3) is not None else (attr_m.group(4) or "")
            )
            if aname not in attrs:
                attrs[aname] = aval

        if tag == "link":
            rel_tokens = {tok for tok in attrs.get("rel", "").lower().split() if tok}
            if "canonical" in rel_tokens and "href" in attrs:
                cand_host = _extract_single_label_url_host(attrs["href"])
                if cand_host and cand_host != base_host:
                    detected.add(cand_host)
        elif tag == "base":
            if "href" in attrs:
                cand_host = _extract_single_label_url_host(attrs["href"])
                if cand_host and cand_host != base_host:
                    detected.add(cand_host)
        elif tag == "a":
            href = attrs.get("href", "")
            cand_host = _extract_single_label_url_host(href)
            if cand_host and cand_host != base_host:
                link_form_counts[cand_host] = link_form_counts.get(cand_host, 0) + 1
        elif tag == "form":
            action = attrs.get("action", "")
            cand_host = _extract_single_label_url_host(action)
            if cand_host and cand_host != base_host:
                link_form_counts[cand_host] = link_form_counts.get(cand_host, 0) + 1

    if link_form_counts:
        max_count = max(link_form_counts.values())
        if max_count >= 3:
            for host, count in link_form_counts.items():
                if count == max_count:
                    detected.add(host)

    return detected


def rewrite_internal_canonical_url(
    raw_url: str,
    *,
    base_url: str,
    canonical_hosts: Iterable[str],
) -> str:
    """Rewrite ``http(s)://<alias>[:port]/path?q`` or ``//<alias>[:port]/path?q`` to ``base_url``.

    Strictly inactive unless ``base_url`` is loopback/RFC1918 and ``<alias>`` is a
    validated single-label hostname present in ``canonical_hosts``.
    """
    raw = str(raw_url or "")
    stripped = raw.strip()
    if not stripped or not is_loopback_or_private_base_url(base_url):
        return raw
    allowed_aliases = {
        h.strip().lower()
        for h in canonical_hosts
        if isinstance(h, str) and is_single_label_internal_host(h)
    }
    if not allowed_aliases:
        return raw

    if stripped.startswith("//"):
        if stripped.startswith("///"):
            return raw
        candidate = f"http:{stripped}"
    elif stripped.lower().startswith(("http://", "https://")):
        candidate = stripped
    else:
        return raw

    try:
        parsed = urlsplit(candidate)
        parsed_base = urlsplit(base_url)
    except ValueError:
        return raw
    if parsed.username is not None or parsed.password is not None:
        return raw
    host = (parsed.hostname or "").strip().lower()
    if host not in allowed_aliases:
        return raw
    if not parsed_base.scheme or not parsed_base.netloc:
        return raw
    return urlunsplit((
        parsed_base.scheme,
        parsed_base.netloc,
        parsed.path or "/",
        parsed.query,
        parsed.fragment,
    ))


def rewrite_internal_canonical_urls_in_text(
    text: str,
    *,
    base_url: str,
    canonical_hosts: Iterable[str],
) -> str:
    """Rewrite validated single-label canonical host URLs inside HTML/JS text to ``base_url``."""
    if not text or not is_loopback_or_private_base_url(base_url):
        return text
    allowed_aliases = sorted(
        {
            h.strip().lower()
            for h in canonical_hosts
            if isinstance(h, str) and is_single_label_internal_host(h)
        },
        key=len,
        reverse=True,
    )
    if not allowed_aliases:
        return text
    parsed_base = urlsplit(base_url)
    if not parsed_base.scheme or not parsed_base.netloc:
        return text
    target_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    hosts_alt = "|".join(re.escape(h) for h in allowed_aliases)
    abs_re = re.compile(
        rf"""\bhttps?://(?:{hosts_alt})(?::\d{{1,5}})?(?=[/?#"'\s<>)]|$)""",
        re.IGNORECASE,
    )
    rel_re = re.compile(
        rf"""(?<![A-Za-z0-9:._/-])//(?:{hosts_alt})(?::\d{{1,5}})?(?=[/?#"'\s<>)]|$)""",
        re.IGNORECASE,
    )
    rewritten = abs_re.sub(target_origin, text)
    return rel_re.sub(target_origin, rewritten)


def infer_openapi_mount_prefix(spec: dict[str, Any], spec_url: str = "") -> str:
    """Infer an OpenAPI/Swagger mount prefix from ``servers``/``basePath`` or a proxied spec URL."""
    if not isinstance(spec, dict):
        return ""
    server_prefix = ""
    servers = spec.get("servers")
    if isinstance(servers, list):
        for srv in servers:
            if not isinstance(srv, dict):
                continue
            srv_url = str(srv.get("url") or "").strip()
            if not srv_url:
                continue
            try:
                srv_path = urlsplit(srv_url).path or ""
            except ValueError:
                continue
            if srv_path and srv_path != "/" and srv_path.startswith("/") and "{" not in srv_path:
                norm_srv = normalize_path(srv_path)
                if norm_srv != "/":
                    server_prefix = norm_srv
                    break
    if not server_prefix:
        raw_base_path = str(spec.get("basePath") or "").strip()
        if raw_base_path and raw_base_path != "/" and raw_base_path.startswith("/") and "{" not in raw_base_path:
            norm_bp = normalize_path(raw_base_path)
            if norm_bp != "/":
                server_prefix = norm_bp
    if server_prefix:
        return server_prefix

    raw_spec = str(spec_url or "").strip()
    if not raw_spec:
        return ""
    try:
        norm_spec = normalize_path(urlsplit(raw_spec).path or "/")
    except ValueError:
        return ""
    low_spec = norm_spec.lower()
    for suffix in _OPENAPI_SPEC_SUFFIXES:
        if low_spec == suffix:
            return ""
        if low_spec.endswith(suffix) and len(norm_spec) > len(suffix):
            prefix = norm_spec[: len(norm_spec) - len(suffix)].rstrip("/")
            if prefix.startswith("/") and prefix != "/":
                return prefix
    return ""


def apply_openapi_path_prefix(raw_path: str, prefix: str) -> str:
    """Prepend ``prefix`` to ``raw_path`` without double-prefixing paths that already carry it."""
    path = str(raw_path or "").strip()
    if not path:
        return path
    if not path.startswith("/"):
        path = "/" + path
    clean_prefix = str(prefix or "").strip().rstrip("/")
    if not clean_prefix or clean_prefix == "/":
        return path
    if not clean_prefix.startswith("/"):
        clean_prefix = "/" + clean_prefix
    low_path = path.lower()
    low_prefix = clean_prefix.lower()
    if low_path == low_prefix or low_path.startswith(low_prefix + "/"):
        return path
    return f"{clean_prefix}{path}"


def _is_auth_utility_path(path: str) -> bool:
    low = (urlsplit(str(path or "")).path or "/").lower()
    return any(f"/{tok}" in low or low.endswith(tok) for tok in _AUTH_PATH_TOKENS)


def is_virgin_state_sensitive_path(path_or_url: str) -> bool:
    """Return True if URL/path contains a whole one-shot or race-sensitive action segment."""
    raw = str(path_or_url or "").strip()
    if not raw:
        return False
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return False
    low_path = (parsed.path or "").strip().lower().rstrip("/")
    if not low_path:
        return False
    if is_static_asset_url(low_path) or low_path.endswith(_VIRGIN_STATIC_ASSET_EXTS):
        return False
    segments = [seg for seg in low_path.split("/") if seg]
    if not segments:
        return False
    if any(seg in _VIRGIN_STATE_IGNORED_SEGMENTS for seg in segments):
        return False
    return any(seg in _VIRGIN_STATE_SENSITIVE_TOKENS for seg in segments)


def _strip_param_marker(param_name: str) -> str:
    raw = str(param_name or "").strip()
    if raw.lower().startswith("path:"):
        raw = raw[5:]
    return raw.rstrip("=").strip()


def is_high_risk_param_name(param_name: str) -> bool:
    """Return True if a query/body/path parameter name belongs to the high-risk input tier."""
    raw = str(param_name or "").strip()
    if not raw:
        return False
    if raw.lower().startswith("path:"):
        return True
    base = _strip_param_marker(raw)
    if not base:
        return False
    base_low = base.lower()
    if base_low in HIGH_RISK_PARAM_NAMES:
        return True
    snake = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", base).lower().replace("-", "_")
    if snake in HIGH_RISK_PARAM_NAMES:
        return True
    if snake.endswith("_id") and len(snake) > 3:
        return True
    tokens = [tok for tok in _TOKEN_SPLIT_RE.split(snake) if tok]
    if len(tokens) >= 2:
        return any(tok in _HIGH_RISK_COMPOUND_PARAM_TOKENS for tok in tokens)
    return False


def is_logout_or_destructive_route(route_or_path: str) -> bool:
    """Return True for logout or destructive host lifecycle routes that must never be nudged."""
    raw = str(route_or_path or "").strip()
    if not raw:
        return False
    try:
        norm_p = normalize_path(urlsplit(raw).path or "/")
    except ValueError:
        return False
    for seg in norm_p.lower().split("/"):
        if not seg:
            continue
        stem = seg.rsplit(".", 1)[0] if "." in seg else seg
        if seg in _LOGOUT_OR_DESTRUCTIVE_SEGMENTS or stem in _LOGOUT_OR_DESTRUCTIVE_SEGMENTS:
            return True
    return False


def _is_active_probe_param_value(val: str) -> bool:
    """Return True when a parameter value contains active security-probe characters rather than a plain benign token."""
    raw = str(val or "").strip()
    if not raw:
        return False
    if ".." in raw:
        return True
    if _BENIGN_QUERY_VAL_RE.fullmatch(raw) is not None:
        return False
    if _BENIGN_EMAIL_VAL_RE.fullmatch(raw) is not None:
        return False
    return True


def _extract_route_family(path: str) -> str:
    """Return the normalized top-level resource family for a URL or route template."""
    raw = str(path or "")
    if is_non_endpoint_source_path(raw):
        return "root"
    if is_catalog_route(raw):
        return "catalog"
    raw_path = urlsplit(raw.strip()).path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    while segments and (
        _ROUTE_FAMILY_PREFIX_RE.fullmatch(segments[0])
        or not any(ch.isalnum() for ch in segments[0])
    ):
        segments.pop(0)
    if not segments:
        return "root"
    first = segments[0]
    if (first.startswith("{") and first.endswith("}")) or first.startswith("$"):
        return "root"
    kv = _split_path_kv_segment(first)
    if kv is not None:
        return kv[0]
    if "=" in first:
        return "root"
    if len(segments) == 1 and "." in first:
        return "root"
    if not any(ch.isalnum() for ch in first):
        return "root"
    return first.lower()


def _extract_api_subfamily(path: str, umbrella: str) -> str | None:
    """Return the normalized non-ID sub-family under an API umbrella prefix, or None."""
    raw = str(path or "")
    raw_path = urlsplit(raw.strip()).path or "/"
    if is_non_endpoint_source_path(raw) or not _ROUTE_API_PATH_RE.search(raw_path):
        return None
    segments = [seg for seg in raw_path.split("/") if seg]
    while segments and (
        _ROUTE_FAMILY_PREFIX_RE.fullmatch(segments[0])
        or not any(ch.isalnum() for ch in segments[0])
    ):
        segments.pop(0)
    if len(segments) < 2 or segments[0].lower() != umbrella.lower():
        return None
    sub = segments[1]
    if is_id_segment(sub) or (sub.startswith("{") and sub.endswith("}")) or not any(ch.isalnum() for ch in sub):
        return None
    kv = _split_path_kv_segment(sub)
    if kv is not None:
        return kv[0]
    if "=" in sub or (len(segments) == 2 and "." in sub):
        return None
    return sub.lower()


def _order_params_by_risk(params: Sequence[str]) -> list[str]:
    """Return deduplicated parameter names ordered high-risk first, then alphabetically."""
    unique = {str(p or "").strip() for p in params if str(p or "").strip()}
    return sorted(
        unique,
        key=lambda p: (
            0 if is_high_risk_param_name(p) else (2 if p.lower() in _HIGH_RISK_LOW_SIGNAL_META_PARAMS else 1),
            p.lower(),
            p,
        ),
    )


def score_route_input_risk(
    route_template: str,
    *,
    methods: Sequence[str] = (),
    params: Sequence[str] = (),
    schema_hints: Sequence[str] = (),
    is_form: bool = False,
    has_body_template: bool = False,
) -> tuple[int, str]:
    """Deterministically score a route template by input attack-surface risk.

    Highest tier: multipart/file-upload endpoints, routes with high-risk query/body/path
    parameter names, and mutating (POST/PUT/PATCH/DELETE) forms/API routes.
    Lower tier: parameterless GET listing/informational pages.
    """
    tmpl = route_template_of(route_template) if str(route_template or "").strip() else "/"
    norm_methods = {str(m or "").strip().upper() for m in methods if str(m or "").strip()}
    mutating_methods = norm_methods & _MUTATING_HTTP_METHODS
    ordered_params = _order_params_by_risk(params)
    high_risk_params = [p for p in ordered_params if is_high_risk_param_name(p)]
    other_params = [
        p
        for p in ordered_params
        if p not in high_risk_params and p.lower() not in _HIGH_RISK_LOW_SIGNAL_META_PARAMS
    ]

    clean_hints = [str(h or "").strip() for h in schema_hints if str(h or "").strip()]
    has_multipart_hint = any(h.lower().startswith("multipart:") for h in clean_hints)

    path_tokens: set[str] = set()
    for seg in tmpl.lower().split("/"):
        if not seg or seg.startswith("{"):
            continue
        stem = seg.rsplit(".", 1)[0] if "." in seg else seg
        for tok in _TOKEN_SPLIT_RE.split(stem):
            if tok:
                path_tokens.add(tok)

    is_upload_path = bool(path_tokens & _UPLOAD_ROUTE_TOKENS)
    is_auth_or_admin_path = bool(path_tokens & _AUTH_ADMIN_ROUTE_TOKENS)
    is_api = bool(_ROUTE_API_PATH_RE.search(tmpl))

    score = 0
    reasons: list[str] = []

    if has_multipart_hint:
        score += 45 + (5 if is_upload_path else 0)
        reasons.append("multipart_upload")
    elif is_upload_path:
        score += 35
        reasons.append("file_upload")

    if high_risk_params:
        score += 30 + min(16, (len(high_risk_params) - 1) * 4) + min(4, len(other_params))
        reasons.append(f"high_risk_params({','.join(high_risk_params[:4])})")
    elif other_params:
        score += 18 + min(8, (len(other_params) - 1) * 2)
        reasons.append(f"parameterized_input({','.join(other_params[:4])})")

    if mutating_methods:
        score += 25 + (4 if has_body_template else 0)
        reasons.append(f"mutating_endpoint({','.join(sorted(mutating_methods))})")
    elif has_body_template:
        score += 20
        reasons.append("body_template")

    if is_form:
        score += 15
        reasons.append("form_endpoint")

    if is_auth_or_admin_path:
        if mutating_methods or is_form or high_risk_params or other_params:
            score += 10
            reasons.append("auth_or_admin")
        else:
            score += 6
            reasons.append("auth_or_admin_page")

    if is_api:
        score += 3
    if "{id}" in tmpl:
        score += 2

    reason_text = ", ".join(reasons) if reasons else "parameterless_get_page"
    return score, reason_text


_ABS_HTTP_URL_CAND_RE = re.compile(r"""https?://[^\s"'<>`()\\]+""", re.IGNORECASE)
_GQL_OP_NAME_RE = re.compile(r"^[_A-Za-z][_0-9A-Za-z]{0,127}$")


def _extract_graphql_op_name(parsed_req: dict[str, Any] | None) -> str:
    """Extract GraphQL operationName or parsed query/mutation root name from a JSON request body."""
    if not isinstance(parsed_req, dict):
        return ""
    op_name = str(parsed_req.get("operationName") or "").strip()
    if op_name and _GQL_OP_NAME_RE.fullmatch(op_name):
        return op_name
    raw_query = parsed_req.get("query")
    if isinstance(raw_query, str) and raw_query.strip():
        try:
            from kryon_core.surface.operation import graphql_operation

            op_info = graphql_operation(raw_query, op_name)
            parsed_name = str(op_info.get("name") or "").strip()
            if parsed_name and _GQL_OP_NAME_RE.fullmatch(parsed_name):
                return parsed_name
            fields = op_info.get("fields") or []
            if fields and isinstance(fields[0], str):
                root_field = fields[0].split(".", 1)[0].strip()
                if root_field and _GQL_OP_NAME_RE.fullmatch(root_field):
                    return root_field
        except Exception:
            pass
    return ""


def _collect_authorized_sibling_origins(
    text: str,
    *,
    primary_url: str,
    scope_guard: ScopeGuard | None,
    limit: int = 12,
) -> list[str]:
    """Return distinct in-scope sibling ``scheme://netloc/`` origins referenced in ``text``."""
    if not text or scope_guard is None or not scope_guard.is_multi_origin:
        return []
    parsed_primary = urlsplit(str(primary_url or "").strip())
    primary_key = (parsed_primary.scheme.lower(), parsed_primary.netloc.lower())
    base_parsed = urlsplit(scope_guard.base_origin)
    base_key = (base_parsed.scheme.lower(), base_parsed.netloc.lower())
    origins: list[str] = []
    seen: set[str] = set()
    for match in _ABS_HTTP_URL_CAND_RE.finditer(text[:524_288]):
        cand = match.group(0).rstrip(".,;:!?]")
        if cand.endswith(")") and "(" not in cand:
            cand = cand[:-1]
        try:
            parsed = urlsplit(cand)
        except ValueError:
            continue
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        if scheme not in {"http", "https"} or not netloc:
            continue
        if (scheme, netloc) in {primary_key, base_key}:
            continue
        origin_url = f"{scheme}://{netloc}/"
        if origin_url in seen:
            continue
        try:
            scope_guard.check_url(cand)
        except ValueError:
            continue
        seen.add(origin_url)
        origins.append(origin_url)
        if len(origins) >= limit:
            break
    return origins


def _explicit_sibling_url_present(body_lower: str, candidate_url: str, sib_netloc_lower: str) -> bool:
    """Return True when ``candidate_url`` explicitly targets ``sib_netloc_lower`` in ``body_lower``."""
    parsed = urlsplit(str(candidate_url or "").strip())
    if parsed.netloc.lower() != sib_netloc_lower:
        return False
    path = (parsed.path or "/").lower()
    path_prefix = path.split("{", 1)[0]
    if f"://{sib_netloc_lower}{path_prefix}" in body_lower:
        return True
    return f"://{sib_netloc_lower}" in body_lower and (path_prefix == "/" or path_prefix in body_lower)


class SurfaceFrontierTracker:
    """Passively tracks discovered routes, per-actor objects, write ops, and untested frontier items."""

    _extract_path_embedded_params = staticmethod(_extract_path_embedded_params)

    def __init__(
        self,
        *,
        base_url: str,
        allowed_methods: Sequence[str] = ("GET", "HEAD"),
        actor_summaries: Sequence[dict[str, str]] = (),
        in_scope_assets: Sequence[str] = (),
        out_of_scope_assets: Sequence[str] = (),
        excluded_paths: Sequence[str] = (),
    ):
        self.base_url = normalize_origin(base_url)
        parsed_origin = urlsplit(self.base_url)
        self._origin = (parsed_origin.scheme, parsed_origin.netloc)
        self.in_scope_assets: tuple[str, ...] = tuple(
            str(x).strip() for x in (in_scope_assets or ()) if str(x or "").strip()
        )
        self.out_of_scope_assets: tuple[str, ...] = tuple(
            str(x).strip() for x in (out_of_scope_assets or ()) if str(x or "").strip()
        )
        self.excluded_paths: tuple[str, ...] = tuple(
            str(x).strip() for x in (excluded_paths or ()) if str(x or "").strip()
        )
        self._scope_guard: ScopeGuard | None = (
            ScopeGuard(
                self.base_url,
                excluded_paths=self.excluded_paths,
                in_scope_assets=self.in_scope_assets,
                out_of_scope_assets=self.out_of_scope_assets,
            )
            if (self.in_scope_assets or self.out_of_scope_assets)
            else None
        )
        self._allow_canonical_host_aliases = is_loopback_or_private_base_url(self.base_url)
        self.internal_canonical_hosts: set[str] = set()
        self.allowed_methods = frozenset(
            str(m).strip().upper() for m in allowed_methods if str(m).strip()
        ) or frozenset({"GET"})
        self.actors: dict[str, dict[str, str]] = {}
        for row in actor_summaries:
            if isinstance(row, dict) and row.get("alias"):
                alias = str(row["alias"]).strip()
                self.actors[alias] = {
                    "alias": alias,
                    "role": str(row.get("role") or "").strip().lower(),
                    "tenant": str(row.get("tenant") or "").strip().lower(),
                }
        if "anon" not in self.actors:
            self.actors["anon"] = {"alias": "anon", "role": "anonymous", "tenant": ""}

        # Track visited endpoints and parameters
        self.exercised_actors: set[str] = set()
        self.visited_method_paths: set[tuple[str, str]] = set()
        self.visited_method_templates: set[tuple[str, str]] = set()
        self.tested_params_by_template: dict[str, set[str]] = {}
        self.param_probes_by_template: dict[str, dict[str, dict[str, Any]]] = {}
        self.html_or_form_templates: set[str] = set()
        self.discovered_form_templates: set[str] = set()
        self.actively_probed_templates: set[str] = set()
        self._non_404_templates: set[str] = set()
        self.actors_by_template: dict[str, set[str]] = {}
        self.actors_by_path: dict[str, set[str]] = {}
        self.route_2xx_actors: dict[str, set[str]] = {}
        self.soft_deny_routes: dict[str, set[str]] = {}
        self.error_delta_params: dict[tuple[str, str], dict[str, Any]] = {}
        self._param_2xx_values: dict[tuple[str, str], set[str]] = {}
        self._param_2xx_status: dict[tuple[str, str], int] = {}
        self._param_500_values: dict[tuple[str, str], set[str]] = {}
        self._2xx_templates: set[str] = set()
        self._spa_route_candidates: set[str] = set()
        self._non_spa_discovered_paths: set[str] = set()
        self.pruned_spa_routes: set[str] = set()
        self._spa_fp_paths: dict[str, set[str]] = {}
        self._suppressed_spa_fingerprints: set[str] = set()
        self.suppressed_spa_fallback_paths: set[str] = set()
        self._spa_404_prefixes: set[str] = set()
        self._spa_shell_prefixes: set[str] = set()
        self._spa_404_templates: set[str] = set()
        self._spa_shell_templates: set[str] = set()
        self._non_fallback_templates: set[str] = set()
        self._template_spa_fps: dict[str, set[str]] = {}
        self._spa_404_candidate_fallback_seen: bool = False

        # Discovered attack surface
        # key: (method, normalized_path) -> sample URL or path with query hint
        self.discovered_routes: dict[tuple[str, str], str] = {}
        # key: route_template -> set of discovered query/form param names
        self.discovered_params: dict[str, set[str]] = {}
        # key: concrete_path -> {"path": str, "template": str, "owner_actor": str, "seen_by": set[str], "listed_by": set[str], "tested_by": set[str], "verified_2xx": bool}
        self.discovered_objects: dict[str, dict[str, Any]] = {}
        # key: concrete_path -> actors whose 2xx collection/list response included this object (unbounded by frontier cap)
        self.collection_listed_objects: dict[str, set[str]] = {}
        self._pruned_404_objects: set[str] = set()
        # key: (method, route_template) -> concrete or sample path
        self.discovered_write_ops: dict[tuple[str, str], str] = {}
        self.declared_write_ops: set[tuple[str, str]] = set()
        self.tested_write_ops: set[tuple[str, str]] = set()
        # Observed API prefixes and non-API UI resource families for UI <-> API parity
        self.api_prefix_routes: dict[str, set[str]] = {}
        self.ui_resource_families: dict[str, dict[str, Any]] = {}
        # Observed working write-body JSON templates and 400/422 validation schema hints
        # key: (METHOD, route_template) -> compacted/redacted JSON object dict
        self.discovered_body_templates: dict[tuple[str, str], dict[str, Any]] = {}
        # key: route_template -> set of validation field hints (e.g. "body.data:list_type")
        self.discovered_schema_hints: dict[str, set[str]] = {}

    def _is_primary_origin(self, scheme: str, netloc: str) -> bool:
        low_s = str(scheme or "").strip().lower()
        low_n = str(netloc or "").strip().lower()
        if (low_s, low_n) == (self._origin[0].lower(), self._origin[1].lower()):
            return True
        try:
            parsed_cand = urlsplit(f"{low_s}://{low_n}")
            parsed_base = urlsplit(self.base_url)
            cand_port = parsed_cand.port or (443 if low_s == "https" else 80)
            base_port = parsed_base.port or (443 if parsed_base.scheme.lower() == "https" else 80)
        except ValueError:
            return False
        return (
            low_s == parsed_base.scheme.lower()
            and (parsed_cand.hostname or "").lower() == (parsed_base.hostname or "").lower()
            and cand_port == base_port
        )

    def _format_scoped_path(self, resolved_url: str) -> str:
        raw = str(resolved_url or "").strip()
        parsed = urlsplit(raw)
        norm_p = normalize_path(parsed.path or "/")
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            if not self._is_primary_origin(parsed.scheme, parsed.netloc):
                return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{norm_p}"
        return norm_p

    def _scoped_template(self, scoped_path: str) -> str:
        raw = str(scoped_path or "").strip()
        if not raw:
            return "/"
        gql_frag = ""
        if "#" in raw:
            base_part, frag_part = raw.split("#", 1)
            clean_frag = frag_part.strip()
            path_low = (urlsplit(base_part).path or "/").lower().rstrip("/")
            if clean_frag and not clean_frag.startswith("/") and path_low.endswith(("/graphql", "/gql")):
                gql_frag = f"#{clean_frag}"
                raw = base_part
        if raw.lower().startswith(("http://", "https://")):
            parsed = urlsplit(raw)
            if parsed.netloc:
                path = parsed.path or "/"
                if self._is_primary_origin(parsed.scheme, parsed.netloc):
                    return route_template_of(path) + gql_frag
                return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{route_template_of(path)}{gql_frag}"
        return route_template_of(raw) + gql_frag

    def _add_discovered_params(self, tmpl: str, names: Sequence[str]) -> None:
        """Add parameter names to `discovered_params[tmpl]` within per-template bounds."""
        if not names:
            return
        bucket = self.discovered_params.setdefault(tmpl, set())
        for raw_name in names:
            pname = str(raw_name or "").strip()
            if not pname or pname in bucket:
                continue
            if len(bucket) >= _MAX_PARAMS_PER_TEMPLATE:
                break
            bucket.add(pname)

    def _record_body_template(self, method: str, tmpl: str, parsed_req: dict[str, Any]) -> None:
        """Record a sanitized, size-bounded observed working JSON body template."""
        if not parsed_req:
            return
        key = (method, tmpl)
        sanitized = _sanitize_json_template(parsed_req)
        if not isinstance(sanitized, dict) or not sanitized:
            return
        fitted = _fit_body_template_budget(sanitized, max_chars=_MAX_BODY_TEMPLATE_CHARS)
        if not fitted:
            return
        existing = self.discovered_body_templates.get(key)
        if existing is None:
            if len(self.discovered_body_templates) >= _MAX_BODY_TEMPLATES:
                return
            self.discovered_body_templates[key] = fitted
        elif len(fitted) > len(existing):
            self.discovered_body_templates[key] = fitted

    def _add_schema_hints(self, tmpl: str, hints: Sequence[str]) -> None:
        """Add compact schema/protocol hints for `tmpl` within per-template and global caps."""
        if not hints or not tmpl:
            return
        existing = self.discovered_schema_hints.get(tmpl)
        if existing is None and len(self.discovered_schema_hints) >= _MAX_SCHEMA_HINT_TEMPLATES:
            return
        bucket = self.discovered_schema_hints.setdefault(tmpl, set())
        for raw_h in hints:
            h = str(raw_h or "").strip()
            if not h or h in bucket:
                continue
            if len(bucket) >= _MAX_SCHEMA_HINTS_PER_TEMPLATE:
                break
            bucket.add(h)

    def _record_multipart_schema(self, tmpl: str, schema: Any) -> list[str]:
        """Record sanitized multipart file/field parameter names and compact schema hints."""
        if not isinstance(schema, dict) or not tmpl:
            return []

        def _clean_names(raw_seq: Any) -> list[str]:
            if not isinstance(raw_seq, (list, tuple, set)):
                return []
            out: list[str] = []
            seen: set[str] = set()
            for item in raw_seq:
                cand = item.get("name") if isinstance(item, dict) else (item if isinstance(item, str) else "")
                clean = _sanitize_multipart_name(cand)
                if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_TEMPLATE:
                    seen.add(clean)
                    out.append(clean)
            return sorted(out)

        files = _clean_names(schema.get("files"))
        fields = _clean_names(schema.get("fields"))
        all_names = sorted(set(files) | set(fields))[:_MAX_PARAMS_PER_TEMPLATE]
        if all_names:
            self._add_discovered_params(tmpl, all_names)
        hints = [*(f"multipart:file={f}" for f in files), *(f"multipart:field={k}" for k in fields)]
        if hints:
            self._add_schema_hints(tmpl, hints)
            self.discovered_form_templates.add(tmpl)
        return all_names

    def _ingest_validation_hints(self, tmpl: str, parsed: Any, *, method: str) -> None:
        """Record 400/422 validation schema hints and leaf parameter names for `tmpl`."""
        hints, leaves = _extract_validation_schema_hints(parsed, method=method)
        if hints:
            self._add_schema_hints(tmpl, hints)
        if leaves:
            self._add_discovered_params(tmpl, leaves)

    def _record_param_probes(self, tmpl: str, pairs: Sequence[tuple[str, str]]) -> None:
        """Record observed parameter names, distinct values (bounded), and special-char probe depth."""
        for k, v in pairs:
            pname = str(k or "").strip()
            if not pname:
                continue
            self.tested_params_by_template.setdefault(tmpl, set()).add(pname)
            val = str(v or "")[:64]
            p_map = self.param_probes_by_template.setdefault(tmpl, {})
            rec = p_map.setdefault(pname, {"values": set(), "has_special": False})
            if len(rec["values"]) < _MAX_PARAM_VALUES_TRACKED:
                rec["values"].add(val)
            if pname.startswith("path:"):
                if val and (".." in val or not _PLAIN_PATH_VAL_RE.fullmatch(val)):
                    rec["has_special"] = True
            elif val and not _PLAIN_ALNUM_VAL_RE.fullmatch(val):
                rec["has_special"] = True

    def _is_param_probed_enough(self, tmpl: str, pname: str) -> bool:
        """Return True once a parameter has sufficient differential or special-character probe depth."""
        p_low = str(pname or "").strip().lower()
        if not p_low or p_low in _NON_PROBE_PARAM_NAMES:
            return True
        rec = (self.param_probes_by_template.get(tmpl) or {}).get(pname)
        if rec is None:
            return pname in (self.tested_params_by_template.get(tmpl) or set())
        if rec.get("has_special"):
            return True
        if len(rec.get("values") or set()) >= 2:
            return True
        needs_depth = (
            p_low.startswith("path:")
            or (tmpl in self.html_or_form_templates)
            or (p_low in _PROBE_PRIORITY_PARAM_NAMES)
        )
        return not needs_depth

    def _upsert_error_delta_param(
        self,
        *,
        key: tuple[str, str],
        norm_p: str,
        method: str,
        baseline_status: int,
        baseline_value: str,
        error_value: str,
    ) -> None:
        """Insert or update a `(route_template, param_name)` 2xx->500 injection candidate."""
        tmpl, pname = key
        existing = self.error_delta_params.get(key)
        if existing is None:
            if len(self.error_delta_params) >= _MAX_ERROR_DELTA_PARAMS:
                return
            self.error_delta_params[key] = {
                "route_template": tmpl,
                "param": pname,
                "sample_path": norm_p,
                "method": method,
                "baseline_status": int(baseline_status),
                "error_status": 500,
                "baseline_value": baseline_value,
                "error_value": error_value,
                "count_500": 1,
            }
        else:
            existing["count_500"] = int(existing.get("count_500") or 0) + 1
            existing["error_value"] = error_value
            if not existing.get("sample_path"):
                existing["sample_path"] = norm_p

    def _record_error_delta_observations(
        self,
        *,
        tmpl: str,
        norm_p: str,
        method: str,
        status: int,
        param_pairs: Sequence[tuple[str, str]],
    ) -> None:
        """Track baseline 2xx vs mutated 500 deltas per `(route_template, param_name)`."""
        if not tmpl or (not (200 <= status < 300) and status != 500):
            return
        if 200 <= status < 300:
            self._2xx_templates.add(tmpl)

        for raw_k, raw_v in param_pairs:
            pname = str(raw_k or "").strip()
            if not pname or pname.lower() in _ROTATING_META_PARAMS or _is_secret_key(pname):
                continue
            val = str(raw_v or "")[:64]
            if "<REDACTED" in val or val == "<redacted>":
                continue
            key = (tmpl, pname)

            if 200 <= status < 300:
                bucket = self._param_2xx_values.get(key)
                if bucket is None:
                    if len(self._param_2xx_values) >= _MAX_ERROR_DELTA_VALUE_TRACKED:
                        continue
                    bucket = set()
                    self._param_2xx_values[key] = bucket
                if len(bucket) < _MAX_PARAM_VALUES_TRACKED:
                    bucket.add(val)
                self._param_2xx_status.setdefault(key, status)

                err_vals = self._param_500_values.get(key) or set()
                if err_vals:
                    diff_err = [ev for ev in sorted(err_vals) if ev not in bucket]
                    if diff_err:
                        self._upsert_error_delta_param(
                            key=key,
                            norm_p=norm_p,
                            method=method,
                            baseline_status=self._param_2xx_status.get(key, status),
                            baseline_value=val,
                            error_value=diff_err[0],
                        )
                    elif key in self.error_delta_params:
                        del self.error_delta_params[key]
            elif status == 500:
                err_bucket = self._param_500_values.get(key)
                if err_bucket is None:
                    if len(self._param_500_values) >= _MAX_ERROR_DELTA_VALUE_TRACKED:
                        continue
                    err_bucket = set()
                    self._param_500_values[key] = err_bucket
                if len(err_bucket) < _MAX_PARAM_VALUES_TRACKED:
                    err_bucket.add(val)

                ok_vals = self._param_2xx_values.get(key) or set()
                if ok_vals:
                    if val not in ok_vals:
                        self._upsert_error_delta_param(
                            key=key,
                            norm_p=norm_p,
                            method=method,
                            baseline_status=self._param_2xx_status.get(key, 200),
                            baseline_value=next(iter(sorted(ok_vals))),
                            error_value=val,
                        )
                elif tmpl in self._2xx_templates and _is_active_probe_param_value(val):
                    self._upsert_error_delta_param(
                        key=key,
                        norm_p=norm_p,
                        method=method,
                        baseline_status=200,
                        baseline_value="",
                        error_value=val,
                    )

    def was_object_listed_for_actor(self, url_or_path: str, actor: str) -> bool:
        """Return True if `actor` legitimately received this concrete object ID in its own 2xx collection listing."""
        clean_actor = str(actor or "").strip()
        if not clean_actor:
            return False
        raw_in = str(url_or_path or "").strip()
        norm_p = self._format_scoped_path(raw_in) if raw_in.lower().startswith(("http://", "https://")) else normalize_path(raw_in)
        if clean_actor in (self.collection_listed_objects.get(norm_p) or set()):
            return True
        entry = self.discovered_objects.get(norm_p)
        if entry and clean_actor in (entry.get("listed_by") or set()):
            return True

        # Check UI <-> API concrete sibling equivalence for the same (resource_family, concrete_id).
        if norm_p.lower().startswith(("http://", "https://")):
            return False
        api_prefix = _extract_api_prefix(norm_p)
        if api_prefix:
            remainder = norm_p[len(api_prefix):].lstrip("/")
            parts = [seg for seg in remainder.split("/") if seg]
            if len(parts) == 2 and is_id_segment(parts[1]):
                ui_sibling = f"/{parts[0].lower()}/{parts[1]}"
                if clean_actor in (self.collection_listed_objects.get(ui_sibling) or set()):
                    return True
                ui_entry = self.discovered_objects.get(ui_sibling)
                if ui_entry and clean_actor in (ui_entry.get("listed_by") or set()):
                    return True
        else:
            info = _extract_ui_resource_info(norm_p)
            if info is not None and info[2]:
                res_name, _, cid = info
                for prefix in self._ranked_api_prefixes():
                    if not prefix.startswith("/"):
                        continue
                    api_sibling = f"{prefix}/{res_name}/{cid}"
                    if clean_actor in (self.collection_listed_objects.get(api_sibling) or set()):
                        return True
                    api_entry = self.discovered_objects.get(api_sibling)
                    if api_entry and clean_actor in (api_entry.get("listed_by") or set()):
                        return True
        return False

    def _known_api_prefixes_for_family(self, resource: str) -> list[str]:
        """Return observed API prefixes that already expose `/<prefix>/<resource>` or `/<prefix>/<resource>/...`."""
        res_low = str(resource or "").strip().lower()
        if not res_low:
            return []
        matched: list[str] = []
        for prefix in self._ranked_api_prefixes():
            if not prefix.startswith("/"):
                continue
            base = f"{prefix}/{res_low}"
            base_slash = f"{base}/"
            in_prefix = any(
                p.lower() == base or p.lower().startswith(base_slash)
                for p in (self.api_prefix_routes.get(prefix) or ())
            )
            in_disc = any(
                not p.lower().startswith(("http://", "https://"))
                and (normalize_path(p).lower() == base or normalize_path(p).lower().startswith(base_slash))
                for _, p in self.discovered_routes
            )
            if in_prefix or in_disc:
                matched.append(prefix)
        return matched

    def _sync_ui_api_concrete_siblings(self, resource: str | None = None) -> None:
        """Register concrete `/api/.../<family>/<id>` siblings for known API families discovered via UI objects."""
        targets = (
            [(resource, self.ui_resource_families[resource])]
            if resource and resource in self.ui_resource_families
            else list(self.ui_resource_families.items())
        )
        for res_name, info in targets:
            prefixes = self._known_api_prefixes_for_family(res_name)
            if not prefixes:
                continue
            primary_prefix = prefixes[0]
            for cid in (info.get("concrete_ids") or [])[:_MAX_OBJECTS_PER_TEMPLATE]:
                api_path = f"{primary_prefix}/{res_name}/{cid}"
                if api_path in self._pruned_404_objects:
                    continue
                ui_path = f"/{res_name}/{cid}"
                ui_entry = self.discovered_objects.get(ui_path) or {}
                owner_hint = str(ui_entry.get("owner_actor") or "")
                seen_actor = owner_hint or next(iter(sorted(ui_entry.get("seen_by") or ())), "")
                already_tested = set(self.actors_by_path.get(api_path) or ())
                if api_path not in self.discovered_objects:
                    self._register_object_path(
                        api_path,
                        actor=seen_actor,
                        owner_hint=owner_hint,
                        visited=bool(already_tested),
                    )
                    if api_path in self.discovered_objects and already_tested:
                        self.discovered_objects[api_path]["tested_by"].update(already_tested)
                elif owner_hint and not self.discovered_objects[api_path].get("owner_actor"):
                    self.discovered_objects[api_path]["owner_actor"] = owner_hint

    def _observe_parity_path(
        self,
        norm_p: str,
        *,
        discovered: bool,
        status: int = 0,
        ctype: str = "",
    ) -> None:
        if is_non_endpoint_source_path(norm_p) or _is_passive_spec_path(norm_p):
            return
        is_sibling = norm_p.lower().startswith(("http://", "https://"))
        api_prefix = _extract_api_prefix(norm_p)
        if api_prefix:
            low_ct = ctype.lower()
            is_json_api_ct = "json" in low_ct or "graphql" in low_ct
            was_discovered = discovered or any(p == norm_p for _, p in self.discovered_routes)
            should_register_api = (
                discovered
                or (200 <= status < 400)
                or (status in (400, 405, 422))
                or (status in (401, 403) and (is_json_api_ct or was_discovered))
            )
            if should_register_api:
                if is_sibling:
                    parsed_s = urlsplit(norm_p)
                    stored_prefix = f"{parsed_s.scheme.lower()}://{parsed_s.netloc.lower()}{api_prefix}"
                    self.api_prefix_routes.setdefault(stored_prefix, set()).add(norm_p)
                else:
                    self.api_prefix_routes.setdefault(api_prefix, set()).add(norm_p)
                    remainder = norm_p[len(api_prefix):].lstrip("/")
                    if remainder:
                        res_seg = remainder.split("/", 1)[0].lower()
                        if res_seg in self.ui_resource_families:
                            self._sync_ui_api_concrete_siblings(res_seg)
            return

        if is_sibling:
            return
        low_ct = ctype.lower()
        if any(tok in low_ct for tok in ("javascript", "ecmascript", "text/css")) or low_ct.startswith(("image/", "font/")):
            return
        if not discovered and status == 404:
            return

        info = _extract_ui_resource_info(norm_p)
        if info is None:
            return
        resource, is_collection, concrete_id = info
        entry = self.ui_resource_families.setdefault(
            resource,
            {"concrete_ids": [], "collection_2xx": False, "collection_403": False},
        )
        if concrete_id and concrete_id not in entry["concrete_ids"]:
            entry["concrete_ids"].append(concrete_id)
        if not discovered and is_collection:
            if 200 <= status < 300:
                entry["collection_2xx"] = True
            elif status in (401, 403):
                entry["collection_403"] = True
        if concrete_id:
            self._sync_ui_api_concrete_siblings(resource)

    def _is_port_in_path_noise(self, url_or_path: str) -> bool:
        """Return True if a path/URL matches a target-port-in-path artifact for this tracker's origin."""
        raw = str(url_or_path or "").strip()
        origin_ref = raw if raw.lower().startswith(("http://", "https://")) else self.base_url
        return is_port_in_path_artifact(raw, origin_url=origin_ref)

    def _resolve_same_origin(self, raw_url: str, current_url: str = "") -> tuple[str, str] | None:
        raw_input = str(raw_url or "")
        if is_non_endpoint_source_path(raw_input):
            return None
        raw = raw_input.strip()
        if self._allow_canonical_host_aliases and self.internal_canonical_hosts and raw:
            raw = rewrite_internal_canonical_url(
                raw,
                base_url=self.base_url,
                canonical_hosts=self.internal_canonical_hosts,
            )
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "//")):
            return None
        base_ref = urljoin(self.base_url, current_url) if current_url else self.base_url
        raw = normalize_bare_hostport_url(raw, base=base_ref)
        if not raw or self._is_port_in_path_noise(raw):
            return None
        resolved = urljoin(base_ref, raw)
        parsed = urlsplit(resolved)
        scheme_low = parsed.scheme.lower()
        netloc_low = parsed.netloc.lower()
        if scheme_low not in {"http", "https"} or not netloc_low:
            return None
        is_primary = self._is_primary_origin(scheme_low, netloc_low)
        if not is_primary:
            if self._scope_guard is None:
                return None
            try:
                self._scope_guard.check_url(resolved)
            except ValueError:
                return None
        elif self._scope_guard is not None:
            try:
                self._scope_guard.check_url(resolved)
            except ValueError:
                return None
        if (is_static_asset_url(parsed.path) and not _extract_path_embedded_params(parsed.path)) or is_non_endpoint_source_path(resolved):
            return None
        norm_p = normalize_path(parsed.path)
        if self._is_port_in_path_noise(norm_p):
            return None
        if not is_primary:
            return f"{scheme_low}://{netloc_low}{norm_p}", parsed.query
        return norm_p, parsed.query

    def _resolve_same_origin_ws(self, raw_url: str, current_url: str = "") -> tuple[str, str] | None:
        """Resolve a WebSocket or relative URL enforcing strict scheme parity (`http`<->`ws`, `https`<->`wss`)."""
        raw = str(raw_url or "").strip()
        if not raw:
            return None
        low = raw.lower()
        if low.startswith("ws://"):
            if self._origin[0] != "http" and self._scope_guard is None:
                return None
            raw = "http://" + raw[5:]
        elif low.startswith("wss://"):
            if self._origin[0] != "https" and self._scope_guard is None:
                return None
            raw = "https://" + raw[6:]
        return self._resolve_same_origin(raw, current_url=current_url)

    def _register_discovered_url(
        self,
        raw_url: str,
        *,
        method: str = "GET",
        params: Sequence[str] = (),
        actor: str = "",
        current_url: str = "",
        is_form: bool = False,
        listed_from_collection: bool = False,
        source_tag: str = "",
        sources: Sequence[str] = (),
    ) -> None:
        norm_method = str(method or "GET").strip().upper()
        resolved = self._resolve_same_origin(raw_url, current_url=current_url)
        if resolved is None:
            return
        norm_p, query = resolved
        if is_non_endpoint_source_path(norm_p):
            return
        tmpl = self._scoped_template(norm_p)

        spa_only = _is_spa_only_source(source_tag, sources)
        neutral_js_string = str(source_tag or "").strip().lower() == "js-string"
        if norm_method == "GET":
            if spa_only:
                if norm_p in self.pruned_spa_routes or (
                    tmpl in self.pruned_spa_routes and tmpl not in self._non_404_templates
                ):
                    return
                if norm_p not in self._non_spa_discovered_paths:
                    self._spa_route_candidates.add(norm_p)
            elif neutral_js_string:
                if norm_p in self.pruned_spa_routes or (
                    tmpl in self.pruned_spa_routes and tmpl not in self._non_404_templates
                ):
                    return
            else:
                self._non_spa_discovered_paths.add(norm_p)
                self._non_spa_discovered_paths.add(tmpl)
                self._spa_route_candidates.discard(norm_p)
                self.pruned_spa_routes.discard(norm_p)

        q_names = [k.strip() for k, _ in parse_qsl(query, keep_blank_values=True) if k.strip()]
        for p in params:
            if isinstance(p, dict):
                pname = str(p.get("name") or "").strip()
            else:
                pname = str(p or "").strip()
            if pname and pname not in q_names:
                q_names.append(pname)
        if q_names:
            self._add_discovered_params(tmpl, q_names)
        path_params = _extract_path_embedded_params(norm_p)
        if path_params:
            self._add_discovered_params(tmpl, path_params)
        if is_form:
            self.html_or_form_templates.add(tmpl)
            self.discovered_form_templates.add(tmpl)

        if norm_method in self.allowed_methods:
            display = f"{norm_p}?{ '&'.join(f'{k}=' for k in q_names[:4]) }" if q_names else norm_p
            key = (norm_method, norm_p)
            should_store_route = True
            if key not in self.discovered_routes and is_catalog_route(tmpl):
                existing_samples = [
                    existing_disp
                    for (m_k, p_k), existing_disp in self.discovered_routes.items()
                    if m_k == norm_method and self._scoped_template(p_k) == tmpl
                ]
                if len(existing_samples) >= _MAX_CATALOG_DISCOVERED_PER_TEMPLATE:
                    existing_qkeys = {
                        k
                        for disp in existing_samples
                        if "?" in disp
                        for k, _ in parse_qsl(disp.split("?", 1)[1], keep_blank_values=True)
                        if k
                    }
                    has_new_q = bool(set(q_names) - existing_qkeys)
                    if not has_new_q:
                        should_store_route = False
            if should_store_route and (
                key not in self.discovered_routes or ("?" in display and "?" not in self.discovered_routes[key])
            ):
                self.discovered_routes[key] = display

        if norm_method in {"POST", "PUT", "PATCH"} and norm_method in self.allowed_methods:
            if not _is_auth_utility_path(norm_p):
                gql_prefix = f"{tmpl}#"
                has_named_gql = (
                    (urlsplit(norm_p).path or "/").lower().rstrip("/").endswith(("/graphql", "/gql"))
                    and any(
                        m_w == norm_method and t_w.startswith(gql_prefix)
                        for m_w, t_w in (*self.declared_write_ops, *self.discovered_write_ops)
                    )
                )
                if not has_named_gql:
                    key_w = (norm_method, tmpl)
                    self.declared_write_ops.add(key_w)
                    existing_sample = self.discovered_write_ops.get(key_w, "")
                    if not existing_sample or ("{" in existing_sample and "{" not in norm_p):
                        self.discovered_write_ops[key_w] = norm_p

        # Check if norm_p is a concrete object URL (has `{id}` in template, not a literal `{...}` template itself).
        if "{id}" in tmpl and "{" not in norm_p and not norm_p.lower().endswith((".js", ".mjs", ".html")):
            self._register_object_path(
                norm_p,
                actor=actor,
                visited=False,
                listed=listed_from_collection,
            )

        self._observe_parity_path(norm_p, discovered=True)

    def _register_object_path(
        self,
        concrete_path: str,
        *,
        actor: str = "",
        owner_hint: str = "",
        visited: bool = False,
        verified_2xx: bool = False,
        listed: bool = False,
    ) -> None:
        if is_non_endpoint_source_path(concrete_path) or self._is_port_in_path_noise(concrete_path):
            return
        raw_c = str(concrete_path or "").strip()
        norm_p = self._format_scoped_path(raw_c) if raw_c.lower().startswith(("http://", "https://")) else normalize_path(raw_c)
        if is_non_endpoint_source_path(norm_p) or self._is_port_in_path_noise(norm_p):
            return
        tmpl = self._scoped_template(norm_p)
        if is_non_endpoint_source_path(tmpl):
            return
        if "{id}" not in tmpl or "{" in norm_p or norm_p.lower().endswith((".js", ".mjs", ".html")):
            return
        clean_actor = str(actor or "").strip()
        clean_owner = str(owner_hint or "").strip()
        if listed and clean_actor:
            self.collection_listed_objects.setdefault(norm_p, set()).add(clean_actor)
        if verified_2xx:
            self._pruned_404_objects.discard(norm_p)
        elif norm_p in self._pruned_404_objects:
            return

        entry = self.discovered_objects.get(norm_p)
        if entry is None:
            tmpl_count = sum(1 for v in self.discovered_objects.values() if v.get("template") == tmpl)
            if tmpl_count >= _MAX_OBJECTS_PER_TEMPLATE and not visited:
                return
            owner = clean_owner if clean_owner in self.actors and clean_owner != "anon" else (
                clean_actor if clean_actor in self.actors and clean_actor != "anon" else ""
            )
            entry = {
                "path": norm_p,
                "template": tmpl,
                "owner_actor": owner,
                "seen_by": {clean_actor} if clean_actor else set(),
                "listed_by": {clean_actor} if (listed and clean_actor) else set(),
                "tested_by": {clean_actor} if (visited and clean_actor) else set(),
                "verified_2xx": bool(verified_2xx),
            }
            self.discovered_objects[norm_p] = entry
        else:
            if verified_2xx:
                entry["verified_2xx"] = True
            if clean_owner and clean_owner in self.actors and clean_owner != "anon":
                entry["owner_actor"] = clean_owner
            elif not entry.get("owner_actor") and clean_actor in self.actors and clean_actor != "anon":
                entry["owner_actor"] = clean_actor
            if clean_actor:
                entry["seen_by"].add(clean_actor)
                if listed:
                    entry.setdefault("listed_by", set()).add(clean_actor)
                if visited:
                    entry["tested_by"].add(clean_actor)

        # If PUT or PATCH is allowed on this target, concrete REST object paths are candidate write ops
        # and also resolve `{id}` placeholders on already-declared OpenAPI/form write operations.
        path_only = urlsplit(norm_p).path or "/"
        if path_only.startswith("/api/") and not _is_auth_utility_path(norm_p):
            for write_m in ("PUT", "PATCH"):
                if write_m in self.allowed_methods:
                    key_w = (write_m, tmpl)
                    existing_sample = self.discovered_write_ops.get(key_w, "")
                    if not existing_sample or "{" in existing_sample:
                        self.discovered_write_ops[key_w] = norm_p

    def _extract_collection_item_paths(self, collection_path: str, parsed_json: Any, actor: str) -> None:
        """Synthesize `/api/.../<collection>/<id>` object paths from plural REST collection JSON responses."""
        raw_col = str(collection_path or "").strip()
        norm_col = self._format_scoped_path(raw_col) if raw_col.lower().startswith(("http://", "https://")) else normalize_path(raw_col)
        col_tmpl = self._scoped_template(norm_col)
        col_path_only = urlsplit(norm_col).path or "/"
        if "{id}" in col_tmpl or not col_path_only.startswith("/api/"):
            return
        last_seg = col_path_only.rsplit("/", 1)[-1].lower().replace("-", "_")
        # Only synthesize `/{id}` on plural collection resource nouns (never on action/export/custom/overview endpoints).
        if not last_seg.endswith("s") or last_seg.endswith(
            ("ss", "us", "is", "status", "details", "settings", "metrics", "analytics")
        ):
            return
        singular = last_seg[:-1] if len(last_seg) > 2 else last_seg
        short_singular = singular.split("_")[-1]
        candidate_id_keys = {
            "id",
            "uuid",
            f"{singular}_id",
            f"{short_singular}_id",
        }

        items: list[dict[str, Any]] = []
        if isinstance(parsed_json, list):
            items = [x for x in parsed_json[:50] if isinstance(x, dict)]
        elif isinstance(parsed_json, dict):
            for v in parsed_json.values():
                if isinstance(v, list):
                    items.extend(x for x in v[:50] if isinstance(x, dict))

        for obj in items[:50]:
            owner_val = ""
            for okey in _OWNER_FIELD_KEYS:
                raw_owner = obj.get(okey)
                if isinstance(raw_owner, str) and raw_owner.strip() in self.actors:
                    owner_val = raw_owner.strip()
                    break
            for k, v in obj.items():
                lk = str(k).lower()
                if lk in candidate_id_keys and isinstance(v, (str, int)) and not isinstance(v, bool):
                    sval = str(v).strip()
                    if sval and len(sval) <= 64 and is_id_segment(sval):
                        obj_path = f"{norm_col}/{sval}"
                        self._register_object_path(
                            obj_path,
                            actor=actor,
                            owner_hint=owner_val,
                            visited=False,
                            listed=True,
                        )
                        if "GET" in self.allowed_methods and obj_path in self.discovered_objects:
                            self.discovered_routes.setdefault(("GET", obj_path), obj_path)
                        break

    def ingest_receipt(self, receipt: dict[str, Any]) -> None:
        """Passively update visited state and extract surface/objects from one HTTP receipt."""
        if not isinstance(receipt, dict):
            return
        actor = str(receipt.get("actor") or "anon").strip() or "anon"
        method = str(receipt.get("method") or "GET").strip().upper()
        raw_url = str(receipt.get("url") or receipt.get("path") or "/")
        url = urljoin(self.base_url, raw_url)
        if self._allow_canonical_host_aliases and self.internal_canonical_hosts:
            url = rewrite_internal_canonical_url(
                url,
                base_url=self.base_url,
                canonical_hosts=self.internal_canonical_hosts,
            )
        status = int(receipt.get("status") or 0)
        body = str(receipt.get("body") or "")
        ctype = str(receipt.get("content_type") or "").lower()

        self.exercised_actors.add(actor)
        norm_p = self._format_scoped_path(url)
        tmpl = self._scoped_template(norm_p)
        parsed_url = urlsplit(url)
        norm_path_low = (urlsplit(norm_p).path or "/").lower().rstrip("/")
        is_graphql_endpoint = norm_path_low.endswith(("/graphql", "/gql"))

        req_body = str(receipt.get("request_body") or "")
        stripped_req = req_body.strip()
        is_multipart_summary = stripped_req.lower().startswith("multipart/form-data ")
        parsed_req_obj: dict[str, Any] | None = None
        if stripped_req and not is_multipart_summary and stripped_req.startswith("{"):
            try:
                cand_req = json.loads(stripped_req)
            except ValueError:
                cand_req = None
            if isinstance(cand_req, dict):
                parsed_req_obj = cand_req
        gql_op_name = (
            _extract_graphql_op_name(parsed_req_obj)
            if (is_graphql_endpoint and parsed_req_obj is not None)
            else ""
        )

        self.visited_method_paths.add((method, norm_p))
        if gql_op_name:
            self.visited_method_paths.add((method, f"{norm_p}#{gql_op_name}"))
            self.visited_method_templates.add((method, f"{tmpl}#{gql_op_name}"))
        else:
            self.visited_method_templates.add((method, tmpl))
        self.actors_by_path.setdefault(norm_p, set()).add(actor)
        self.actors_by_template.setdefault(tmpl, set()).add(actor)
        if status and status != 404:
            self._non_404_templates.add(tmpl)

        active_probe_tmpl = tmpl
        raw_norm_p = normalize_path(str(receipt.get("path") or raw_url))
        raw_path_pairs = _extract_path_embedded_param_pairs(raw_norm_p)
        path_param_pairs = _extract_path_embedded_param_pairs(norm_p)
        observed_param_pairs: list[tuple[str, str]] = []
        if raw_path_pairs and not path_param_pairs:
            raw_tmpl = (
                f"{parsed_url.scheme.lower()}://{parsed_url.netloc.lower()}{route_template_of(raw_norm_p)}"
                if (
                    parsed_url.scheme.lower() in {"http", "https"}
                    and parsed_url.netloc
                    and not self._is_primary_origin(parsed_url.scheme, parsed_url.netloc)
                )
                else route_template_of(raw_norm_p)
            )
            active_probe_tmpl = raw_tmpl
            if status != 404:
                self._add_discovered_params(raw_tmpl, [k for k, _ in raw_path_pairs])
                self._non_404_templates.add(raw_tmpl)
            concrete_raw_pairs = [(k, v) for k, v in raw_path_pairs if v or k.endswith("=")]
            if concrete_raw_pairs:
                self._record_param_probes(raw_tmpl, concrete_raw_pairs)
                observed_param_pairs.extend(concrete_raw_pairs)
        elif path_param_pairs:
            if status != 404:
                self._add_discovered_params(tmpl, [k for k, _ in path_param_pairs])
            concrete_path_pairs = [(k, v) for k, v in path_param_pairs if v or k.endswith("=")]
            if concrete_path_pairs:
                self._record_param_probes(tmpl, concrete_path_pairs)
                observed_param_pairs.extend(concrete_path_pairs)

        query_str = str(receipt.get("query") or parsed_url.query or "")
        q_pairs = [(k.strip(), v) for k, v in parse_qsl(query_str, keep_blank_values=True) if k.strip()]
        if q_pairs:
            self._record_param_probes(tmpl, q_pairs)
            observed_param_pairs.extend(q_pairs)

        if method in _MUTATING_HTTP_METHODS:
            if is_graphql_endpoint and gql_op_name:
                self.actively_probed_templates.add(f"{tmpl}#{gql_op_name}")
            else:
                self.actively_probed_templates.add(tmpl)
                if active_probe_tmpl != tmpl:
                    self.actively_probed_templates.add(active_probe_tmpl)
        elif observed_param_pairs:
            self._maybe_mark_param_actively_probed(active_probe_tmpl, observed_param_pairs)
            if active_probe_tmpl != tmpl and q_pairs:
                self._maybe_mark_param_actively_probed(tmpl, q_pairs)

        is_html_resp = (
            "html" in ctype
            or "<html" in body[:512].lower()
            or "<!doctype" in body[:512].lower()
            or "<form" in body.lower()
        )
        raw_len = receipt.get("response_length")
        if isinstance(raw_len, int) and not isinstance(raw_len, bool) and raw_len >= 0:
            resp_len = raw_len
        elif isinstance(raw_len, str) and raw_len.strip().isdigit():
            resp_len = int(raw_len.strip())
        else:
            resp_len = len(body.encode("utf-8", errors="replace")) if body else 0
        raw_sha = str(receipt.get("response_sha256") or "").strip().lower()
        if not raw_sha and body:
            raw_sha = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

        is_trackable_spa_html = (
            method == "GET"
            and is_html_resp
            and (
                (status == 404 and resp_len >= _SPA_404_MIN_BYTES)
                or (200 <= status < 400 and resp_len >= _SPA_SHELL_MIN_BYTES)
            )
            and bool(raw_sha or resp_len > 0)
        )
        is_suppressed_spa_fp = False
        if is_trackable_spa_html:
            fp_key = (
                f"{status}:sha256:{raw_sha[:32]}"
                if raw_sha
                else f"{status}:len:{resp_len}"
            )
            if fp_key in self._spa_fp_paths or len(self._spa_fp_paths) < _MAX_SPA_FP_BUCKETS:
                bucket = self._spa_fp_paths.setdefault(fp_key, set())
                if len(bucket) < _MAX_SPA_FP_PATHS_PER_BUCKET:
                    bucket.add(norm_p)
            else:
                bucket = set()

            if 200 <= status < 400 and "<form" not in body.lower():
                tmpl_fps = self._template_spa_fps.setdefault(tmpl, set())
                if len(tmpl_fps) < 8:
                    tmpl_fps.add(fp_key)
                if len(tmpl_fps) >= 2:
                    self._non_fallback_templates.add(tmpl)
                    self._spa_shell_templates.discard(tmpl)

            if fp_key in self._suppressed_spa_fingerprints or len(bucket) >= 3:
                self._suppressed_spa_fingerprints.add(fp_key)
                is_suppressed_spa_fp = True
                self.suppressed_spa_fallback_paths.add(norm_p)
                self.suppressed_spa_fallback_paths.update(bucket)

                if status == 404:
                    spa_cand_hits = 0
                    for p in bucket:
                        if p in self._spa_route_candidates:
                            spa_cand_hits += 1
                            self.pruned_spa_routes.add(p)
                            self.discovered_routes.pop(("GET", p), None)
                    if spa_cand_hits >= 3:
                        self._spa_404_candidate_fallback_seen = True

                prefix_counts: dict[str, int] = {}
                tmpl_counts: dict[str, int] = {}
                for p in bucket:
                    p_segs = [s for s in (urlsplit(p).path or "/").split("/") if s]
                    p_prefix = "/" + "/".join(p_segs[:-1]) if len(p_segs) > 1 else "/"
                    if p_prefix != "/":
                        prefix_counts[p_prefix] = prefix_counts.get(p_prefix, 0) + 1
                    p_tmpl = self._scoped_template(p)
                    tmpl_counts[p_tmpl] = tmpl_counts.get(p_tmpl, 0) + 1
                    if 200 <= status < 400 and p_tmpl not in self._non_fallback_templates and p_tmpl not in self.discovered_form_templates:
                        self.html_or_form_templates.discard(p_tmpl)
                    p_info = _extract_ui_resource_info(p)
                    if p_info is not None and p_info[0] in self.ui_resource_families:
                        fam_entry = self.ui_resource_families[p_info[0]]
                        if not fam_entry.get("concrete_ids") and not fam_entry.get("collection_403"):
                            self.ui_resource_families.pop(p_info[0], None)

                for p_prefix, cnt in prefix_counts.items():
                    if cnt >= 3:
                        if status == 404:
                            self._spa_404_prefixes.add(p_prefix)
                        else:
                            self._spa_shell_prefixes.add(p_prefix)
                for p_tmpl, cnt in tmpl_counts.items():
                    if cnt >= 3 and p_tmpl not in self._non_fallback_templates:
                        if status == 404:
                            self._spa_404_templates.add(p_tmpl)
                        else:
                            self._spa_shell_templates.add(p_tmpl)
        elif 200 <= status < 400:
            self._non_fallback_templates.add(tmpl)
            self._spa_404_templates.discard(tmpl)
            self._spa_shell_templates.discard(tmpl)
            self.suppressed_spa_fallback_paths.discard(norm_p)
            p_segs = [s for s in (urlsplit(norm_p).path or "/").split("/") if s]
            p_prefix = "/" + "/".join(p_segs[:-1]) if len(p_segs) > 1 else "/"
            if p_prefix != "/" and actor != "anon":
                self._spa_shell_prefixes.discard(p_prefix)

        is_redirect_resp = 300 <= status < 400 and bool(str(receipt.get("redirect_location") or "").strip())
        if 200 <= status < 400 and (is_html_resp or is_redirect_resp) and not (is_suppressed_spa_fp and "<form" not in body.lower()):
            self.html_or_form_templates.add(tmpl)
            if q_pairs:
                non_meta_keys = {k for k, _ in q_pairs if k.lower() not in _NON_PROBE_PARAM_NAMES}
                if non_meta_keys:
                    self.discovered_params.setdefault(tmpl, set()).update(non_meta_keys)

        body_probe_pairs: list[tuple[str, str]] = []
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            bt_tmpl = f"{tmpl}#{gql_op_name}" if (is_graphql_endpoint and gql_op_name) else tmpl
            if parsed_req_obj is not None:
                json_probe_pairs = [
                    (str(k).strip(), "<redacted>" if _is_secret_key(str(k)) else str(v)[:64])
                    for k, v in list(parsed_req_obj.items())[:_MAX_BODY_TEMPLATE_DICT_KEYS]
                    if str(k).strip()
                ]
                if json_probe_pairs:
                    self._record_param_probes(bt_tmpl, json_probe_pairs)
                    if bt_tmpl != tmpl:
                        self._record_param_probes(tmpl, json_probe_pairs)
                    body_probe_pairs.extend(json_probe_pairs)
                if method in {"POST", "PUT", "PATCH"} and 200 <= status < 400 and parsed_req_obj:
                    self._record_body_template(method, bt_tmpl, parsed_req_obj)
            elif stripped_req and not is_multipart_summary and not stripped_req.startswith(("{", "[")):
                body_pairs = [(k.strip(), v) for k, v in parse_qsl(req_body, keep_blank_values=True) if k.strip()]
                if body_pairs:
                    self._record_param_probes(tmpl, body_pairs)
                    body_probe_pairs.extend(body_pairs)
            if not _is_auth_utility_path(norm_p):
                if is_graphql_endpoint and gql_op_name:
                    self.tested_write_ops.add((method, f"{tmpl}#{gql_op_name}"))
                else:
                    self.tested_write_ops.add((method, tmpl))

        delta_pairs = [*observed_param_pairs, *body_probe_pairs]
        self._record_error_delta_observations(
            tmpl=active_probe_tmpl,
            norm_p=norm_p,
            method=method,
            status=status,
            param_pairs=delta_pairs,
        )
        if active_probe_tmpl != tmpl and (q_pairs or body_probe_pairs):
            self._record_error_delta_observations(
                tmpl=tmpl,
                norm_p=norm_p,
                method=method,
                status=status,
                param_pairs=[*q_pairs, *body_probe_pairs],
            )

        is_soft_deny = False
        if 200 <= status < 300:
            is_soft_deny = _is_soft_deny_200(receipt, method=method, status=status, body=body)
            if is_soft_deny:
                if actor not in (self.route_2xx_actors.get(norm_p) or ()):
                    self.soft_deny_routes.setdefault(norm_p, set()).add(actor)
            else:
                self.route_2xx_actors.setdefault(norm_p, set()).add(actor)
                if norm_p in self.soft_deny_routes:
                    self.soft_deny_routes[norm_p].discard(actor)
                    if not self.soft_deny_routes[norm_p]:
                        del self.soft_deny_routes[norm_p]

        if method == "GET" and status == 404:
            if (
                (norm_p in self._spa_route_candidates or tmpl in self._spa_route_candidates)
                and norm_p not in self._non_spa_discovered_paths
                and tmpl not in self._non_spa_discovered_paths
            ):
                if norm_p in self._spa_route_candidates:
                    self.pruned_spa_routes.add(norm_p)
                    self.discovered_routes.pop(("GET", norm_p), None)
                if tmpl in self._spa_route_candidates and tmpl not in self._non_404_templates:
                    self.pruned_spa_routes.add(tmpl)
                    self.discovered_routes.pop(("GET", tmpl), None)
        elif status and status != 404:
            self.pruned_spa_routes.discard(norm_p)

        if not is_suppressed_spa_fp:
            self._observe_parity_path(norm_p, discovered=False, status=status, ctype=ctype)

        # Track concrete object visits
        if "{id}" in tmpl and "{" not in norm_p and 200 <= status < 300 and not is_soft_deny:
            owner_hint = ""
            if body.lstrip().startswith("{"):
                try:
                    obj_json = json.loads(body)
                except ValueError:
                    obj_json = None
                if isinstance(obj_json, dict):
                    for okey in _OWNER_FIELD_KEYS:
                        val = obj_json.get(okey)
                        if isinstance(val, str) and val.strip() in self.actors:
                            owner_hint = val.strip()
                            break
            self._register_object_path(
                norm_p,
                actor=actor,
                owner_hint=owner_hint,
                visited=True,
                verified_2xx=True,
            )
        elif norm_p in self.discovered_objects:
            obj_entry = self.discovered_objects[norm_p]
            if status == 404 and not obj_entry.get("verified_2xx") and (
                actor == obj_entry.get("owner_actor") or not obj_entry.get("owner_actor")
            ):
                del self.discovered_objects[norm_p]
                self.discovered_routes.pop(("GET", norm_p), None)
                self._pruned_404_objects.add(norm_p)
            else:
                obj_entry["tested_by"].add(actor)

        # Follow same-origin / in-scope redirect Location
        loc = str(receipt.get("redirect_location") or "").strip()
        if not loc:
            resp_hdrs = receipt.get("response_headers")
            if isinstance(resp_hdrs, dict):
                loc = str(resp_hdrs.get("Location") or resp_hdrs.get("location") or "").strip()

        if self._allow_canonical_host_aliases:
            low_body_hint = body.lower() if body else ""
            html_for_canonical = (
                body
                if (
                    is_html_resp
                    or "href=" in low_body_hint
                    or "action=" in low_body_hint
                    or "<link" in low_body_hint
                    or "<base" in low_body_hint
                )
                else ""
            )
            detected_aliases = detect_internal_canonical_hosts(
                html_for_canonical,
                base_url=self.base_url,
                location_header=loc,
            )
            if detected_aliases:
                self.internal_canonical_hosts.update(detected_aliases)

        if loc:
            self._register_discovered_url(loc, method="GET", actor=actor, current_url=url)

        if not body or status >= 500:
            return

        extract_body = (
            rewrite_internal_canonical_urls_in_text(
                body,
                base_url=self.base_url,
                canonical_hosts=self.internal_canonical_hosts,
            )
            if (self._allow_canonical_host_aliases and self.internal_canonical_hosts)
            else body
        )

        is_collection_2xx = (200 <= status < 300) and ("{id}" not in tmpl) and norm_p != "/"
        col_prefix = f"{norm_p}/"
        is_multi_origin = bool(self._scope_guard is not None and self._scope_guard.is_multi_origin)
        sibling_origins = (
            _collect_authorized_sibling_origins(
                extract_body,
                primary_url=url,
                scope_guard=self._scope_guard,
            )
            if is_multi_origin
            else []
        )
        extract_body_low = extract_body.lower() if sibling_origins else ""

        # Passive extraction from JSON / OpenAPI / HTML / JS / robots / sitemap
        stripped = body.lstrip()
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                if status in {400, 422}:
                    self._ingest_validation_hints(tmpl, parsed, method=method)
                if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                    self._ingest_openapi_spec(parsed, spec_url=url)
                hypermedia_origin = url if is_multi_origin else self.base_url
                hypermedia, _ = extract_json_hypermedia(parsed, url, origin_url=hypermedia_origin)
                if sibling_origins:
                    for sib_orig in sibling_origins:
                        sib_hm, _ = extract_json_hypermedia(parsed, url, origin_url=sib_orig)
                        hypermedia.extend(sib_hm)
                for item in hypermedia:
                    raw_hm_url = str(item.get("url") or "")
                    hm_resolved = self._resolve_same_origin(raw_hm_url, current_url=url)
                    hm_listed = bool(
                        is_collection_2xx
                        and hm_resolved is not None
                        and hm_resolved[0].startswith(col_prefix)
                    )
                    self._register_discovered_url(
                        raw_hm_url,
                        method=str(item.get("method") or "GET"),
                        params=item.get("params") or (),
                        actor=actor,
                        current_url=url,
                        listed_from_collection=hm_listed,
                    )
                if 200 <= status < 300:
                    self._extract_collection_item_paths(norm_p, parsed, actor)
                spec_candidates = list(find_spec_urls(extract_body, url, allow_subdomains=is_multi_origin))
                for sib_orig in sibling_origins:
                    sib_netloc = urlsplit(sib_orig).netloc.lower()
                    for cand_u in find_spec_urls(extract_body, sib_orig, allow_subdomains=True):
                        if _explicit_sibling_url_present(extract_body_low, cand_u, sib_netloc):
                            spec_candidates.append(cand_u)
                for spec_u in spec_candidates:
                    self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if is_html_resp or "href=" in body.lower() or "action=" in body.lower():
            html_records = list(extract_html(extract_body, url, allow_subdomains=is_multi_origin))
            if sibling_origins:
                for sib_orig in sibling_origins:
                    sib_netloc = urlsplit(sib_orig).netloc.lower()
                    for rec in extract_html(extract_body, sib_orig, allow_subdomains=True):
                        if _explicit_sibling_url_present(extract_body_low, str(rec.get("url") or ""), sib_netloc):
                            html_records.append(rec)
            for rec in html_records:
                raw_h_url = str(rec.get("url") or "")
                h_resolved = self._resolve_same_origin(raw_h_url, current_url=url)
                h_listed = bool(
                    is_collection_2xx
                    and h_resolved is not None
                    and h_resolved[0].startswith(col_prefix)
                )
                self._register_discovered_url(
                    raw_h_url,
                    method=str(rec.get("method") or "GET"),
                    params=rec.get("params") or (),
                    actor=actor,
                    current_url=url,
                    is_form=(rec.get("sources") == ["form"]),
                    listed_from_collection=h_listed,
                )
            for script in extract_inline_scripts(extract_body):
                script_low = script.lower() if sibling_origins else ""
                base_jcs = extract_js_calls(script, url, allow_subdomains=is_multi_origin, limit=40)
                base_jc_sigs = {(str(c.get("method") or "GET").upper(), urlsplit(str(c.get("url") or "")).path) for c in base_jcs}
                all_jcs = list(base_jcs)
                for sib_orig in sibling_origins:
                    sib_netloc = urlsplit(sib_orig).netloc.lower()
                    for jc in extract_js_calls(script, sib_orig, allow_subdomains=True, limit=40):
                        jc_u = str(jc.get("url") or "")
                        jc_p = urlsplit(jc_u)
                        if jc_p.netloc.lower() != sib_netloc:
                            continue
                        sig = (str(jc.get("method") or "GET").upper(), jc_p.path)
                        if sig not in base_jc_sigs or _explicit_sibling_url_present(script_low, jc_u, sib_netloc):
                            all_jcs.append(jc)
                for jc in all_jcs:
                    self._register_discovered_url(
                        str(jc.get("url") or ""),
                        method=str(jc.get("method") or "GET"),
                        params=jc.get("params") or (),
                        actor=actor,
                        current_url=url,
                    )
                for sr in extract_spa_routes(script, url, allow_subdomains=is_multi_origin, limit=40):
                    self._register_discovered_url(
                        str(sr.get("url") or ""),
                        method="GET",
                        actor=actor,
                        current_url=url,
                        sources=sr.get("sources") or ("spa-route",),
                    )
                script_specs = list(find_spec_urls(script, url, allow_subdomains=is_multi_origin))
                for sib_orig in sibling_origins:
                    sib_netloc = urlsplit(sib_orig).netloc.lower()
                    for cand_u in find_spec_urls(script, sib_orig, allow_subdomains=True):
                        if _explicit_sibling_url_present(script_low, cand_u, sib_netloc):
                            script_specs.append(cand_u)
                for spec_u in script_specs:
                    self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if "javascript" in ctype or norm_path_low.endswith((".js", ".mjs")):
            base_jcs = extract_js_calls(extract_body, url, allow_subdomains=is_multi_origin, limit=80)
            base_jc_sigs = {(str(c.get("method") or "GET").upper(), urlsplit(str(c.get("url") or "")).path) for c in base_jcs}
            all_jcs = list(base_jcs)
            for sib_orig in sibling_origins:
                sib_netloc = urlsplit(sib_orig).netloc.lower()
                for jc in extract_js_calls(extract_body, sib_orig, allow_subdomains=True, limit=80):
                    jc_u = str(jc.get("url") or "")
                    jc_p = urlsplit(jc_u)
                    if jc_p.netloc.lower() != sib_netloc:
                        continue
                    sig = (str(jc.get("method") or "GET").upper(), jc_p.path)
                    if sig not in base_jc_sigs or _explicit_sibling_url_present(extract_body_low, jc_u, sib_netloc):
                        all_jcs.append(jc)
            for jc in all_jcs:
                self._register_discovered_url(
                    str(jc.get("url") or ""),
                    method=str(jc.get("method") or "GET"),
                    params=jc.get("params") or (),
                    actor=actor,
                    current_url=url,
                )
            kept_js = 0
            base_js_recs = extract_js(extract_body, url, allow_subdomains=is_multi_origin, limit=240)
            base_js_paths = {urlsplit(str(r.get("url") or "")).path for r in base_js_recs}
            all_js_recs = list(base_js_recs)
            for sib_orig in sibling_origins:
                sib_netloc = urlsplit(sib_orig).netloc.lower()
                for rec in extract_js(extract_body, sib_orig, allow_subdomains=True, limit=240):
                    rec_u = str(rec.get("url") or "")
                    rec_p = urlsplit(rec_u)
                    if rec_p.netloc.lower() != sib_netloc:
                        continue
                    if rec_p.path not in base_js_paths or _explicit_sibling_url_present(extract_body_low, rec_u, sib_netloc):
                        all_js_recs.append(rec)
            for rec in all_js_recs:
                cand_u = str(rec.get("url") or "")
                if is_non_endpoint_source_path(cand_u):
                    continue
                self._register_discovered_url(
                    cand_u,
                    method=str(rec.get("method") or "GET"),
                    params=rec.get("params") or (),
                    actor=actor,
                    current_url=url,
                    source_tag="js-string",
                )
                kept_js += 1
                if kept_js >= 60:
                    break
            kept_spa = 0
            for sr in extract_spa_routes(extract_body, url, allow_subdomains=is_multi_origin, limit=160):
                cand_u = str(sr.get("url") or "")
                if is_non_endpoint_source_path(cand_u):
                    continue
                self._register_discovered_url(
                    cand_u,
                    method="GET",
                    actor=actor,
                    current_url=url,
                    sources=sr.get("sources") or ("spa-route",),
                )
                kept_spa += 1
                if kept_spa >= 60:
                    break
            js_specs = list(find_spec_urls(extract_body, url, allow_subdomains=is_multi_origin))
            for sib_orig in sibling_origins:
                sib_netloc = urlsplit(sib_orig).netloc.lower()
                for cand_u in find_spec_urls(extract_body, sib_orig, allow_subdomains=True):
                    if _explicit_sibling_url_present(extract_body_low, cand_u, sib_netloc):
                        js_specs.append(cand_u)
            for spec_u in js_specs:
                self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if norm_path_low.endswith("/robots.txt"):
            for rec in extract_robots(body, url):
                self._register_discovered_url(str(rec.get("url") or ""), method="GET", actor=actor, current_url=url)
        if "xml" in ctype or "<urlset" in body[:512].lower() or "<sitemapindex" in body[:512].lower():
            sitemap_recs = list(extract_sitemap(extract_body, url, allow_subdomains=is_multi_origin))
            for sib_orig in sibling_origins:
                sib_netloc = urlsplit(sib_orig).netloc.lower()
                for rec in extract_sitemap(extract_body, sib_orig, allow_subdomains=True):
                    if _explicit_sibling_url_present(extract_body_low, str(rec.get("url") or ""), sib_netloc):
                        sitemap_recs.append(rec)
            for rec in sitemap_recs:
                self._register_discovered_url(str(rec.get("url") or ""), method="GET", actor=actor, current_url=url)

    def _resolve_openapi_target_origin(self, spec: dict[str, Any], *, spec_url: str = "") -> str:
        """Resolve an in-scope target origin from OpenAPI ``servers`` or Swagger 2 ``host``, falling back to ``spec_url``/``base_url``."""
        servers = spec.get("servers")
        if isinstance(servers, list):
            for srv in servers:
                if not isinstance(srv, dict):
                    continue
                srv_url = str(srv.get("url") or "").strip()
                if not srv_url:
                    continue
                if srv_url.lower().startswith(("http://", "https://")):
                    parsed_srv = urlsplit(srv_url)
                    if "{" in parsed_srv.netloc or not parsed_srv.netloc:
                        continue
                    if self._resolve_same_origin(f"{parsed_srv.scheme.lower()}://{parsed_srv.netloc}/") is not None:
                        return f"{parsed_srv.scheme.lower()}://{parsed_srv.netloc.lower()}/"
                    break

        raw_host = str(spec.get("host") or "").strip()
        if raw_host and "{" not in raw_host:
            raw_schemes = spec.get("schemes")
            schemes = (
                [str(s).strip().lower() for s in raw_schemes if str(s).strip().lower() in {"http", "https"}]
                if isinstance(raw_schemes, list)
                else []
            )
            fallback_scheme = (
                urlsplit(spec_url).scheme.lower()
                if spec_url and urlsplit(spec_url).scheme.lower() in {"http", "https"}
                else self._origin[0].lower()
            )
            chosen_scheme = "https" if "https" in schemes else (schemes[0] if schemes else fallback_scheme)
            cand_origin = f"{chosen_scheme}://{raw_host}/"
            if self._resolve_same_origin(cand_origin) is not None:
                return cand_origin.lower()

        if spec_url:
            parsed_spec = urlsplit(str(spec_url).strip())
            if parsed_spec.scheme.lower() in {"http", "https"} and parsed_spec.netloc:
                spec_origin = f"{parsed_spec.scheme.lower()}://{parsed_spec.netloc.lower()}/"
                if self._resolve_same_origin(spec_origin) is not None:
                    return spec_origin
        return self.base_url

    def _ingest_openapi_spec(self, spec: dict[str, Any], *, spec_url: str = "") -> None:
        resolver = LocalSchema(spec)
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return
        target_origin = self._resolve_openapi_target_origin(spec, spec_url=spec_url)
        mount_prefix = infer_openapi_mount_prefix(spec, spec_url)
        for raw_path, path_item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(path_item, dict):
                continue
            eff_path = apply_openapi_path_prefix(raw_path, mount_prefix)
            raw_path_params = path_item.get("parameters")
            path_params = raw_path_params if isinstance(raw_path_params, list) else []
            for method_low in ("get", "post", "put", "patch", "delete", "head"):
                op = path_item.get(method_low)
                if not isinstance(op, dict):
                    continue
                m_up = method_low.upper()
                q_params: list[str] = []
                raw_op_params = op.get("parameters")
                op_params = raw_op_params if isinstance(raw_op_params, list) else []
                for p in [*path_params, *op_params]:
                    resolved_p = resolver.resolve(p) if isinstance(p, dict) else {}
                    pname = resolved_p.get("name")
                    pin = str(resolved_p.get("in") or "query").lower()
                    if pname and pin == "query":
                        q_params.append(str(pname))
                self._register_discovered_url(
                    eff_path,
                    method=m_up,
                    params=q_params,
                    current_url=target_origin,
                )

    def ingest_surface(self, surface: dict[str, Any], *, actor: str = "") -> None:
        """Ingest structured output of `extract_surface` tool into the frontier tracker."""
        if not isinstance(surface, dict):
            return
        curr_url = str(surface.get("url") or self.base_url)

        def _ingest_item_schemas(raw_url: str, method: str, item: dict[str, Any]) -> None:
            norm_method = str(method or "GET").strip().upper()
            if norm_method not in self.allowed_methods:
                return
            resolved = self._resolve_same_origin(raw_url, current_url=curr_url)
            if resolved is None:
                return
            norm_p, _ = resolved
            tmpl = self._scoped_template(norm_p)
            bt = item.get("body_template")
            if isinstance(bt, dict) and bt and norm_method in {"POST", "PUT", "PATCH"}:
                self._record_body_template(norm_method, tmpl, bt)
            mp = item.get("multipart_schema")
            if isinstance(mp, dict) and mp:
                self._record_multipart_schema(tmpl, mp)

        for item in (surface.get("forms") or []):
            if isinstance(item, dict):
                item_url = str(item.get("url") or "")
                item_method = str(item.get("method") or "GET")
                self._register_discovered_url(
                    item_url,
                    method=item_method,
                    params=item.get("params") or (),
                    actor=actor,
                    current_url=curr_url,
                    is_form=True,
                )
                _ingest_item_schemas(item_url, item_method, item)
        batch_spa_paths: set[str] = set()
        for item in (surface.get("spa_routes") or []):
            if isinstance(item, dict):
                raw_spa_u = str(item.get("url") or "")
                res_spa = self._resolve_same_origin(raw_spa_u, current_url=curr_url)
                if res_spa is not None:
                    batch_spa_paths.add(res_spa[0])

        for is_link_bucket, bucket in (
            (True, surface.get("links") or ()),
            (False, surface.get("js_calls") or ()),
        ):
            for item in bucket:
                if not isinstance(item, dict):
                    continue
                item_url = str(item.get("url") or "")
                item_method = str(item.get("method") or "GET")
                item_tag = str(item.get("source_tag") or "")
                item_sources = item.get("sources") or ()
                if is_link_bucket and not item_tag and not item_sources and batch_spa_paths:
                    res_link = self._resolve_same_origin(item_url, current_url=curr_url)
                    if res_link is not None and res_link[0] in batch_spa_paths:
                        item_tag = "spa-route"
                self._register_discovered_url(
                    item_url,
                    method=item_method,
                    params=item.get("params") or (),
                    actor=actor,
                    current_url=curr_url,
                    source_tag=item_tag,
                    sources=item_sources,
                )
                _ingest_item_schemas(item_url, item_method, item)
                if not is_link_bucket and isinstance(item.get("operation"), dict):
                    op_meta = item["operation"]
                    if op_meta.get("protocol") == "graphql":
                        op_name = str(op_meta.get("name") or "").strip()
                        res_gql = self._resolve_same_origin(item_url, current_url=curr_url)
                        norm_m = str(item_method or "POST").strip().upper()
                        if (
                            op_name
                            and _GQL_OP_NAME_RE.fullmatch(op_name)
                            and res_gql is not None
                            and norm_m in {"POST", "PUT", "PATCH"}
                            and norm_m in self.allowed_methods
                            and not _is_auth_utility_path(res_gql[0])
                        ):
                            gql_norm = res_gql[0]
                            gql_tmpl = self._scoped_template(gql_norm)
                            op_tmpl = f"{gql_tmpl}#{op_name}"
                            self.declared_write_ops.add((norm_m, op_tmpl))
                            self.discovered_write_ops[(norm_m, op_tmpl)] = f"{gql_norm}#{op_name}"
                            self.declared_write_ops.discard((norm_m, gql_tmpl))
                            self.discovered_write_ops.pop((norm_m, gql_tmpl), None)
        for item in (surface.get("spa_routes") or []):
            if isinstance(item, dict):
                item_url = str(item.get("url") or "")
                item_method = str(item.get("method") or "GET")
                item_tag = str(item.get("source_tag") or "")
                item_sources = item.get("sources") or ()
                if not item_tag and not item_sources:
                    item_tag = "spa-route"
                self._register_discovered_url(
                    item_url,
                    method=item_method,
                    params=item.get("params") or (),
                    actor=actor,
                    current_url=curr_url,
                    source_tag=item_tag,
                    sources=item_sources,
                )
                _ingest_item_schemas(item_url, item_method, item)
        for spec_u in (surface.get("spec_urls") or []):
            if isinstance(spec_u, str):
                self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=curr_url)
        for op in (surface.get("openapi_operations") or []):
            if isinstance(op, dict):
                pnames = [
                    str(p.get("name"))
                    for p in (op.get("params") or [])
                    if isinstance(p, dict) and p.get("name") and p.get("in") == "query"
                ]
                self._register_discovered_url(
                    str(op.get("url") or op.get("path") or ""),
                    method=str(op.get("method") or "GET"),
                    params=pnames,
                    actor=actor,
                    current_url=curr_url,
                )
        for pop in (surface.get("postman_ops") or []):
            if isinstance(pop, dict):
                self._register_discovered_url(
                    str(pop.get("url") or ""),
                    method=str(pop.get("method") or "GET"),
                    params=pop.get("body_keys") or (),
                    actor=actor,
                    current_url=curr_url,
                )
        client_logic = surface.get("client_logic")
        if isinstance(client_logic, dict):
            for ep in (client_logic.get("endpoints") or []):
                if isinstance(ep, dict):
                    ep_url = str(ep.get("path") or ep.get("url") or "")
                    ep_params = [
                        *(ep.get("query_params") or []),
                        *(ep.get("body_fields") or []),
                    ]
                    self._register_discovered_url(
                        ep_url,
                        method=str(ep.get("method") or "GET"),
                        params=ep_params,
                        actor=actor,
                        current_url=curr_url,
                    )
        if surface.get("graphql_ops") and curr_url:
            self._register_discovered_url(
                curr_url,
                method="POST",
                actor=actor,
                current_url=curr_url,
            )
            res_gql = self._resolve_same_origin(curr_url, current_url=curr_url)
            if (
                res_gql is not None
                and "POST" in self.allowed_methods
                and not _is_auth_utility_path(res_gql[0])
            ):
                gql_norm = res_gql[0]
                gql_tmpl = self._scoped_template(gql_norm)
                added_named_gql = False
                for gop in (surface.get("graphql_ops") or []):
                    if not isinstance(gop, dict):
                        continue
                    op_name = str(gop.get("name") or "").strip()
                    if not op_name or not _GQL_OP_NAME_RE.fullmatch(op_name):
                        continue
                    added_named_gql = True
                    op_tmpl = f"{gql_tmpl}#{op_name}"
                    self.declared_write_ops.add(("POST", op_tmpl))
                    self.discovered_write_ops[("POST", op_tmpl)] = f"{gql_norm}#{op_name}"
                    raw_args = gop.get("args")
                    if isinstance(raw_args, list) and raw_args:
                        self._add_discovered_params(op_tmpl, [str(a) for a in raw_args if a])
                if added_named_gql:
                    self.declared_write_ops.discard(("POST", gql_tmpl))
                    self.discovered_write_ops.pop(("POST", gql_tmpl), None)

        body_templates = surface.get("body_templates")
        if isinstance(body_templates, dict):
            for raw_key, doc in body_templates.items():
                if not isinstance(raw_key, str) or not isinstance(doc, dict) or not doc:
                    continue
                m_key = _METHOD_URL_KEY_RE.fullmatch(raw_key.strip())
                if m_key is None:
                    continue
                bt_method = m_key.group(1).upper()
                bt_path = m_key.group(2)
                if bt_method not in self.allowed_methods:
                    continue
                resolved = self._resolve_same_origin(bt_path, current_url=curr_url)
                if resolved is None:
                    continue
                norm_p, _ = resolved
                tmpl = self._scoped_template(norm_p)
                top_keys = [
                    clean
                    for k in doc
                    if (clean := _sanitize_multipart_name(k))
                ][:_MAX_PARAMS_PER_TEMPLATE]
                self._register_discovered_url(
                    bt_path,
                    method=bt_method,
                    params=top_keys,
                    actor=actor,
                    current_url=curr_url,
                )
                if bt_method in {"POST", "PUT", "PATCH"}:
                    self._record_body_template(bt_method, tmpl, doc)

        multipart_schemas = surface.get("multipart_schemas")
        if isinstance(multipart_schemas, dict):
            for raw_key, schema in multipart_schemas.items():
                if not isinstance(raw_key, str) or not isinstance(schema, dict) or not schema:
                    continue
                m_key = _METHOD_URL_KEY_RE.fullmatch(raw_key.strip())
                if m_key is None:
                    continue
                mp_method = m_key.group(1).upper()
                mp_path = m_key.group(2)
                if mp_method not in self.allowed_methods:
                    continue
                resolved = self._resolve_same_origin(mp_path, current_url=curr_url)
                if resolved is None:
                    continue
                norm_p, _ = resolved
                tmpl = self._scoped_template(norm_p)
                mp_params = self._record_multipart_schema(tmpl, schema)
                self._register_discovered_url(
                    mp_path,
                    method=mp_method,
                    params=mp_params,
                    actor=actor,
                    current_url=curr_url,
                    is_form=True,
                )

        ws_endpoints = surface.get("ws_endpoints")
        if isinstance(ws_endpoints, list):
            for ws_item in ws_endpoints:
                raw_ws = ""
                if isinstance(ws_item, str):
                    raw_ws = ws_item.strip()
                elif isinstance(ws_item, dict):
                    raw_ws = str(ws_item.get("url") or ws_item.get("path") or "").strip()
                if not raw_ws:
                    continue
                resolved_ws = self._resolve_same_origin_ws(raw_ws, current_url=curr_url)
                if resolved_ws is None:
                    continue
                norm_p, query = resolved_ws
                tmpl = self._scoped_template(norm_p)
                if "GET" in self.allowed_methods:
                    ws_target = f"{norm_p}?{query}" if query else norm_p
                    self._register_discovered_url(
                        ws_target,
                        method="GET",
                        actor=actor,
                        current_url=curr_url,
                    )
                self._add_schema_hints(tmpl, ["ws:upgrade"])

    def unvisited_routes(self) -> list[str]:
        """Return discovered routes and parameterized endpoints not yet tested."""
        candidates: list[tuple[tuple[int, str, str], str]] = []
        seen_templates_in_out: set[tuple[str, str]] = set()
        has_non_anon_actors = any(a != "anon" for a in self.actors)
        for (method, norm_p), display in sorted(self.discovered_routes.items()):
            if (
                method not in self.allowed_methods
                or is_non_endpoint_source_path(norm_p)
                or self._is_port_in_path_noise(norm_p)
                or is_os_filesystem_path(norm_p)
                or is_hashed_asset_chunk_path(norm_p)
                or (is_static_asset_url(norm_p) and not _extract_path_embedded_params(norm_p))
            ):
                continue
            tmpl = self._scoped_template(norm_p)
            if method == "GET" and (
                norm_p in self.pruned_spa_routes
                or (tmpl in self.pruned_spa_routes and tmpl not in self._non_404_templates)
            ):
                continue
            norm_path_only = urlsplit(norm_p).path or "/"
            is_api = bool(_ROUTE_API_PATH_RE.search(norm_path_only))
            disc_p = self.discovered_params.get(tmpl) or set()
            has_params = bool(disc_p) or ("?" in display)
            is_form = tmpl in self.discovered_form_templates
            is_write = (method in _MUTATING_HTTP_METHODS) or any(
                w_t == tmpl for _, w_t in (*self.declared_write_ops, *self.discovered_write_ops)
            )
            p_segs = [s for s in norm_path_only.split("/") if s]
            parent_prefix = "/" + "/".join(p_segs[:-1]) if len(p_segs) > 1 else "/"
            is_demoted_spa = False
            if method == "GET" and not is_api and not has_params and not is_form and not is_write:
                if norm_p in self.suppressed_spa_fallback_paths:
                    continue
                if (
                    tmpl in self._spa_404_templates or tmpl in self._spa_shell_templates
                ) and tmpl not in self._non_fallback_templates:
                    continue
                if parent_prefix != "/":
                    if parent_prefix in self._spa_404_prefixes:
                        continue
                    if parent_prefix in self._spa_shell_prefixes:
                        root_seg = p_segs[0].lower() if p_segs else ""
                        if root_seg in _FUNCTIONAL_ROOT_SEGMENTS and has_non_anon_actors:
                            is_demoted_spa = True
                        else:
                            continue
                if self._spa_404_candidate_fallback_seen and norm_p in self._spa_route_candidates:
                    is_demoted_spa = True

            if is_catalog_route(tmpl) and not has_params and not is_form and not is_write:
                rank_tier = 2
            elif is_demoted_spa:
                rank_tier = 1
            else:
                rank_tier = 0

            # Skip unexpanded OpenAPI template strings `{...}` if a concrete path for that template was visited
            if "{" in norm_p and (method, tmpl) in self.visited_method_templates:
                continue
            if (method, norm_p) not in self.visited_method_paths and (method, tmpl) not in self.visited_method_templates:
                if (method, tmpl) not in seen_templates_in_out:
                    seen_templates_in_out.add((method, tmpl))
                    path_p = sorted(
                        k for k in disc_p if str(k).startswith("path:")
                    )
                    suffix = f" [{','.join(path_p[:2])}]" if path_p else ""
                    candidates.append(((rank_tier, method, norm_p), f"{method} {display}{suffix}"))
            else:
                # Check if discovered query/form/path parameters on this route template remain completely untested
                tested_p = self.tested_params_by_template.get(tmpl) or set()
                untested_p = sorted(disc_p - tested_p)
                if untested_p and (method, tmpl) not in seen_templates_in_out:
                    seen_templates_in_out.add((method, tmpl))
                    query_untested = [k for k in untested_p if not str(k).startswith("path:")]
                    path_untested = [k for k in untested_p if str(k).startswith("path:")]
                    if query_untested and path_untested:
                        param_hint = "&".join(f"{k}=" for k in query_untested[:4])
                        label = f"{method} {norm_p}?{param_hint} [{','.join(path_untested[:2])}]"
                    elif query_untested:
                        param_hint = "&".join(f"{k}=" for k in query_untested[:4])
                        label = f"{method} {norm_p}?{param_hint}"
                    else:
                        label = f"{method} {norm_p} [{','.join(path_untested[:2])}]"
                    candidates.append(((0, method, norm_p), label))
        candidates.sort(key=lambda pair: pair[0])
        return [label for _, label in candidates]

    def unprobed_params(self) -> list[str]:
        """Return discovered query/path params on visited routes that only received a single benign value."""
        out: list[str] = []
        visited_tmpls = {tmpl for _, tmpl in self.visited_method_templates}
        sample_path_by_tmpl: dict[str, str] = {}
        for _, path in sorted(self.visited_method_paths):
            t = self._scoped_template(path)
            if t not in sample_path_by_tmpl:
                sample_path_by_tmpl[t] = path

        for tmpl, disc_p in sorted(self.discovered_params.items()):
            if (
                tmpl not in visited_tmpls
                or _is_auth_utility_path(tmpl)
                or (tmpl in self.pruned_spa_routes and tmpl not in self._non_404_templates)
            ):
                continue
            tested_p = self.tested_params_by_template.get(tmpl) or set()
            shallow = [
                pname
                for pname in sorted(disc_p)
                if pname in tested_p and not self._is_param_probed_enough(tmpl, pname)
            ]
            if not shallow:
                continue
            sample_path = sample_path_by_tmpl.get(tmpl, tmpl)
            for pname in shallow[:2]:
                if str(pname).startswith("path:"):
                    out.append(
                        f"GET {sample_path} [{pname}] (1 benign value seen; probe traversal/URL/injection value)"
                    )
                else:
                    out.append(f"GET {sample_path}?{pname}= (1 benign value seen; probe special-char/differential value)")
                if len(out) >= 8:
                    return out
        return out

    def _recommended_cross_actors(self, owner_actor: str) -> list[str]:
        """Return ordered peer/cross-tenant/anon actors to cross-test an object owned by `owner_actor`."""
        owner_meta = self.actors.get(owner_actor) or {}
        owner_tenant = owner_meta.get("tenant", "")
        owner_role = owner_meta.get("role", "")

        same_tenant_same_role: list[str] = []
        same_tenant_other: list[str] = []
        cross_tenant: list[str] = []
        others: list[str] = []

        for alias, meta in sorted(self.actors.items()):
            if alias == owner_actor or alias == "anon":
                continue
            role = meta.get("role", "")
            tenant = meta.get("tenant", "")
            if "admin" in role:
                continue
            if owner_tenant and tenant == owner_tenant:
                if owner_role and role == owner_role:
                    same_tenant_same_role.append(alias)
                else:
                    same_tenant_other.append(alias)
            elif owner_tenant and tenant and tenant != owner_tenant:
                cross_tenant.append(alias)
            else:
                others.append(alias)

        candidates = [*same_tenant_same_role[:1], *cross_tenant[:1], *same_tenant_other[:1], *others[:1]]
        if not candidates and "anon" in self.actors and owner_actor != "anon":
            candidates.append("anon")
        return candidates

    def _missing_actors_for_object(self, info: dict[str, Any]) -> list[str]:
        """Return missing same-tenant peer and cross-tenant actors for a concrete object."""
        owner = str(info.get("owner_actor") or "")
        listed_by = set(info.get("listed_by") or ())
        tested_by = set(info.get("tested_by") or ())
        seen_by = set(info.get("seen_by") or ())

        ref_actor = owner
        if not ref_actor:
            for pool in (listed_by, seen_by, tested_by):
                non_anon = [
                    a for a in sorted(pool)
                    if a in self.actors and a != "anon" and "admin" not in (self.actors[a].get("role") or "")
                ]
                if non_anon:
                    ref_actor = non_anon[0]
                    break

        if not ref_actor:
            # Unknown owner: require coverage from up to 2 non-admin actors across distinct tenants when available.
            non_admin = [
                (alias, meta.get("tenant", ""))
                for alias, meta in sorted(self.actors.items())
                if alias != "anon" and "admin" not in meta.get("role", "")
            ]
            if not non_admin:
                return ["anon"] if ("anon" in self.actors and "anon" not in tested_by) else []
            by_tenant: dict[str, list[str]] = {}
            for alias, tenant in non_admin:
                by_tenant.setdefault(tenant, []).append(alias)
            missing_unknown: list[str] = []
            for tenant_key in sorted(by_tenant):
                t_actors = by_tenant[tenant_key]
                if not any(a in tested_by for a in t_actors):
                    missing_unknown.append(t_actors[0])
                if len(missing_unknown) >= 2:
                    break
            if not missing_unknown and len(non_admin) >= 2 and len(tested_by) < 2:
                for alias, _ in non_admin:
                    if alias not in tested_by:
                        missing_unknown.append(alias)
                        break
            return missing_unknown

        ref_meta = self.actors.get(ref_actor) or {}
        ref_tenant = ref_meta.get("tenant", "")
        ref_role = ref_meta.get("role", "")

        same_tenant_peers: list[str] = []
        cross_tenant_actors: list[str] = []
        other_actors: list[str] = []

        for alias, meta in sorted(self.actors.items()):
            if alias == ref_actor or alias == "anon":
                continue
            role = meta.get("role", "")
            tenant = meta.get("tenant", "")
            if "admin" in role:
                continue
            if ref_tenant and tenant == ref_tenant:
                same_tenant_peers.append(alias)
            elif ref_tenant and tenant and tenant != ref_tenant:
                cross_tenant_actors.append(alias)
            else:
                other_actors.append(alias)

        same_tenant_peers.sort(
            key=lambda a: (
                0 if a not in listed_by else 1,
                0 if (ref_role and (self.actors.get(a) or {}).get("role", "") == ref_role) else 1,
                a,
            )
        )
        cross_tenant_actors.sort(key=lambda a: (0 if a not in listed_by else 1, a))

        missing: list[str] = []
        if same_tenant_peers:
            unlisted_peers = [p for p in same_tenant_peers if p not in listed_by]
            peer_pool = unlisted_peers if unlisted_peers else ([] if tested_by else same_tenant_peers)
            if peer_pool and not any(p in tested_by for p in peer_pool):
                missing.append(peer_pool[0])

        if cross_tenant_actors:
            unlisted_xt = [c for c in cross_tenant_actors if c not in listed_by]
            xt_pool = unlisted_xt if unlisted_xt else cross_tenant_actors
            if xt_pool and not any(c in tested_by for c in xt_pool):
                missing.append(xt_pool[0])

        if not same_tenant_peers and not cross_tenant_actors:
            if other_actors:
                if not any(o in tested_by for o in other_actors):
                    missing.append(other_actors[0])
            elif "anon" in self.actors and ref_actor != "anon" and "anon" not in tested_by:
                missing.append("anon")

        return missing

    def untested_cross_actor_objects(self) -> list[str]:
        """Return concrete object endpoints and role/auth API routes not yet cross-tested."""
        if len(self.actors) <= 1:
            return []
        out: list[str] = []

        non_admin_actors = [
            a for a, m in sorted(self.actors.items())
            if a != "anon" and "admin" not in m.get("role", "")
        ]
        # 1. Privileged/admin routes that returned 2xx for admin but have NOT been tested by a non-admin actor (BFLA frontier)
        if non_admin_actors:
            for norm_p, ok_actors in sorted(self.route_2xx_actors.items()):
                if is_non_endpoint_source_path(norm_p):
                    continue
                tmpl = self._scoped_template(norm_p)
                if "{id}" in tmpl or _is_auth_utility_path(norm_p):
                    continue
                tested_on_path = self.actors_by_path.get(norm_p) or set()
                admin_ok = [a for a in ok_actors if "admin" in (self.actors.get(a) or {}).get("role", "")]
                if (admin_ok or "/admin" in norm_p) and not any(na in tested_on_path for na in non_admin_actors):
                    sample_na = non_admin_actors[0]
                    src_actor = admin_ok[0] if admin_ok else next(iter(ok_actors), "admin")
                    out.append(f"GET {norm_p} (privileged route 200 as {src_actor}; replay_as {sample_na} for BFLA)")

        # 2. Authenticated non-object API routes that returned 2xx but have NOT been tested as 'anon' (auth_bypass frontier)
        if "anon" in self.actors:
            for norm_p, ok_actors in sorted(self.route_2xx_actors.items()):
                if is_non_endpoint_source_path(norm_p):
                    continue
                tmpl = self._scoped_template(norm_p)
                path_only = urlsplit(norm_p).path or "/"
                if "{id}" in tmpl or not path_only.startswith("/api/") or _is_auth_utility_path(norm_p):
                    continue
                tested_on_path = self.actors_by_path.get(norm_p) or set()
                if "anon" not in tested_on_path and any(a != "anon" for a in ok_actors):
                    src_actor = next(a for a in sorted(ok_actors) if a != "anon")
                    out.append(f"GET {norm_p} (API 200 as {src_actor}; replay_as anon for auth_bypass)")

        # 3. Per-concrete-object ({id}) frontier across same-tenant peer & cross-tenant dimensions (bounded per template)
        ordered_objects = sorted(
            self.discovered_objects.items(),
            key=lambda kv: (
                len(kv[1].get("tested_by") or ()),
                0 if (urlsplit(kv[0]).path or "/").startswith("/api/") else 1,
                kv[0],
            ),
        )
        for norm_p, info in ordered_objects:
            if is_non_endpoint_source_path(norm_p) or self._is_port_in_path_noise(norm_p):
                continue
            missing = self._missing_actors_for_object(info)
            if not missing:
                continue
            tested_by = info.get("tested_by") or set()
            owner = str(info.get("owner_actor") or "") or next(iter(sorted(info.get("seen_by") or ())), "")
            peers_str = ",".join(missing[:2])
            if not tested_by:
                out.append(f"GET {norm_p} (untested object, owner={owner or 'unknown'}; test as {peers_str})")
            else:
                out.append(f"GET {norm_p} (owner={owner or 'unknown'}; replay_as {peers_str})")
        return out

    def untested_write_ops(self) -> list[str]:
        """Return discovered mutating operations (`POST`/`PUT`/`PATCH`) not yet probed, declared first."""
        write_allowed = self.allowed_methods & {"POST", "PUT", "PATCH"}
        if not write_allowed:
            return []
        concrete_by_tmpl: dict[str, str] = {}
        for norm_p, info in sorted(self.discovered_objects.items()):
            tmpl = info.get("template") or ""
            if tmpl and "{" not in norm_p and tmpl not in concrete_by_tmpl:
                concrete_by_tmpl[tmpl] = norm_p

        ranked: list[tuple[tuple[int, int, int, str, str], str]] = []
        for (method, tmpl), sample_path in self.discovered_write_ops.items():
            if method not in write_allowed:
                continue
            if (
                is_non_endpoint_source_path(sample_path)
                or is_non_endpoint_source_path(tmpl)
                or self._is_port_in_path_noise(sample_path)
                or self._is_port_in_path_noise(tmpl)
                or _is_auth_utility_path(sample_path)
                or _is_auth_utility_path(tmpl)
            ):
                continue
            if (method, tmpl) in self.tested_write_ops:
                continue
            resolved_path = concrete_by_tmpl.get(tmpl, sample_path) if "{" in sample_path else sample_path
            is_declared = 0 if (method, tmpl) in self.declared_write_ops else 1
            has_placeholder = 1 if "{" in resolved_path else 0
            method_rank = 0 if method in {"PUT", "PATCH"} else 1
            ranked.append(((is_declared, has_placeholder, method_rank, resolved_path, method), f"{method} {resolved_path}"))
        ranked.sort(key=lambda pair: pair[0])
        return [label for _, label in ranked]

    def untested_actors(self) -> list[str]:
        """Return configured actors that have not yet executed any HTTP request."""
        return [alias for alias in sorted(self.actors) if alias not in self.exercised_actors]

    def _ranked_api_prefixes(self) -> list[str]:
        ranked: list[tuple[tuple[int, int, int, int, str], str]] = []
        for prefix, paths in self.api_prefix_routes.items():
            non_util = sum(1 for p in paths if not _is_non_resource_api_subpath(prefix, p))
            is_versioned = 1 if "/v" in prefix else 0
            ranked.append(((1 if non_util > 0 else 0, non_util, is_versioned, len(paths), prefix), prefix))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [prefix for _, prefix in ranked]

    def _has_visited_api_resource(self, resource: str) -> bool:
        prefixes = list(self.api_prefix_routes.keys())
        if not prefixes:
            return False
        visited_paths = {p.lower() for _, p in self.visited_method_paths}
        visited_tmpls = {t.lower() for _, t in self.visited_method_templates}
        for prefix in prefixes:
            base = f"{prefix}/{resource}"
            base_slash = f"{base}/"
            if any(vp == base or vp.startswith(base_slash) for vp in visited_paths):
                return True
            if any(vt == base or vt.startswith(base_slash) for vt in visited_tmpls):
                return True
        return False

    def untested_api_parity(self) -> list[str]:
        """Return inferred API-parity candidates for UI resource families not yet probed under an observed API prefix."""
        prefixes = [p for p in self._ranked_api_prefixes() if p.startswith("/")]
        if not prefixes:
            return []
        primary_prefix = prefixes[0]
        probe_method = "GET" if "GET" in self.allowed_methods else next(iter(sorted(self.allowed_methods)), "GET")

        candidates: list[tuple[tuple[int, int, int, str], str]] = []
        for resource, info in self.ui_resource_families.items():
            if (
                _NUMERIC_SLUG_CATEGORY_RE.match(resource) is not None
                or _is_passive_spec_path(f"{primary_prefix}/{resource}")
                or self._has_visited_api_resource(resource)
            ):
                continue
            concrete_ids = info.get("concrete_ids") or []
            col_2xx = bool(info.get("collection_2xx"))
            col_403 = bool(info.get("collection_403"))
            if not concrete_ids and not col_2xx and not col_403:
                continue
            if concrete_ids:
                path = f"{primary_prefix}/{resource}/{concrete_ids[0]}"
            else:
                path = f"{primary_prefix}/{resource}"
            rank_key = (
                0 if concrete_ids else 1,
                0 if col_2xx else 1,
                0 if col_403 else 1,
                resource,
            )
            candidates.append((rank_key, f"{probe_method} {path}"))

        candidates.sort(key=lambda pair: pair[0])
        return [label for _, label in candidates]

    def _template_known_methods(self, tmpl: str) -> tuple[set[str], set[str]]:
        """Return `(all_methods, allowed_methods)` observed or declared for `tmpl`."""
        all_methods: set[str] = set()
        for m, norm_p in self.discovered_routes:
            if self._scoped_template(norm_p) == tmpl:
                all_methods.add(str(m or "GET").strip().upper())
        for m, v_tmpl in self.visited_method_templates:
            if v_tmpl == tmpl:
                all_methods.add(str(m or "GET").strip().upper())
        for m, w_tmpl in self.declared_write_ops:
            if w_tmpl == tmpl:
                all_methods.add(str(m or "POST").strip().upper())
        for m, w_tmpl in self.discovered_write_ops:
            if w_tmpl == tmpl:
                all_methods.add(str(m or "POST").strip().upper())
        for m, bt_tmpl in self.discovered_body_templates:
            if bt_tmpl == tmpl:
                all_methods.add(str(m or "POST").strip().upper())
        allowed = all_methods & self.allowed_methods
        return all_methods, allowed

    def _requires_mutating_probe(self, tmpl: str, allowed_methods: set[str]) -> bool:
        """Return True when `tmpl` is a multipart/upload or write-only endpoint requiring a mutating probe."""
        if not (allowed_methods & _MUTATING_HTTP_METHODS):
            return False
        hints = self.discovered_schema_hints.get(tmpl) or ()
        if any(str(h).lower().startswith("multipart:") for h in hints):
            return True
        path_tokens = {
            tok
            for seg in (urlsplit(tmpl).path or "/").lower().split("/")
            if seg and not seg.startswith("{")
            for tok in _TOKEN_SPLIT_RE.split(seg.rsplit(".", 1)[0] if "." in seg else seg)
            if tok
        }
        if path_tokens & _UPLOAD_ROUTE_TOKENS:
            return True
        return "GET" not in allowed_methods and "HEAD" not in allowed_methods

    def _maybe_mark_param_actively_probed(
        self,
        tmpl: str,
        pairs: Sequence[tuple[str, str]],
    ) -> None:
        """Mark `tmpl` as actively probed when query/path params show >=2 value variants or an active probe payload."""
        if not tmpl or not pairs:
            return
        _, allowed_methods = self._template_known_methods(tmpl)
        if self._requires_mutating_probe(tmpl, allowed_methods):
            return
        pmap = self.param_probes_by_template.get(tmpl) or {}
        for raw_k, raw_v in pairs:
            pname = str(raw_k or "").strip()
            if not pname or pname.lower() in _HIGH_RISK_LOW_SIGNAL_META_PARAMS:
                continue
            val = str(raw_v or "")[:64]
            if _is_active_probe_param_value(val):
                self.actively_probed_templates.add(tmpl)
                return
            rec = pmap.get(pname)
            if rec is not None and len(rec.get("values") or ()) >= 2:
                self.actively_probed_templates.add(tmpl)
                return

    def is_route_actively_probed(
        self,
        route_template: str,
        *,
        methods: Sequence[str] | None = None,
    ) -> bool:
        """Return True if `route_template` has been actively probed rather than merely passively observed."""
        tmpl = self._scoped_template(route_template) if str(route_template or "").strip() else "/"
        if tmpl in self.actively_probed_templates:
            return True
        if any(
            m in _MUTATING_HTTP_METHODS and t == tmpl
            for m, t in (*self.visited_method_templates, *self.tested_write_ops)
        ):
            return True
        if methods is not None:
            allowed_methods = {str(m or "").strip().upper() for m in methods if str(m or "").strip()} & self.allowed_methods
        else:
            _, allowed_methods = self._template_known_methods(tmpl)
        if self._requires_mutating_probe(tmpl, allowed_methods):
            return False
        pmap = self.param_probes_by_template.get(tmpl) or {}
        for pname, rec in pmap.items():
            if not pname or pname.lower() in _HIGH_RISK_LOW_SIGNAL_META_PARAMS:
                continue
            vals = rec.get("values") or ()
            if len(vals) >= 2 or any(_is_active_probe_param_value(str(v)) for v in vals):
                return True
        return False

    def score_route_risk(
        self,
        route_template: str,
        *,
        methods: Sequence[str] | None = None,
        params: Sequence[str] | None = None,
    ) -> tuple[int, str]:
        """Score `route_template` using this tracker's known methods, params, forms, and schemas."""
        tmpl = self._scoped_template(route_template) if str(route_template or "").strip() else "/"
        if methods is None:
            _, allowed = self._template_known_methods(tmpl)
            eff_methods = sorted(allowed) if allowed else (["GET"] if "GET" in self.allowed_methods else sorted(self.allowed_methods)[:1])
        else:
            eff_methods = [str(m or "").strip().upper() for m in methods if str(m or "").strip()]
        if params is None:
            p_set = set(self.discovered_params.get(tmpl) or ())
            p_set.update((self.param_probes_by_template.get(tmpl) or {}).keys())
            eff_params = _order_params_by_risk(sorted(p_set))
        else:
            eff_params = _order_params_by_risk(params)
        hints = sorted(self.discovered_schema_hints.get(tmpl) or ())
        has_bt = any(t == tmpl for _, t in self.discovered_body_templates)
        return score_route_input_risk(
            tmpl,
            methods=eff_methods,
            params=eff_params,
            schema_hints=hints,
            is_form=(tmpl in self.discovered_form_templates),
            has_body_template=has_bt,
        )

    def high_risk_unprobed_routes(
        self,
        allowed_families: set[str] | None = None,
        limit: int = 8,
    ) -> list[dict[str, Any]]:
        """Return deterministically ranked high-risk parameterized/upload/form/mutating routes not yet actively probed."""
        cap = max(0, int(limit))
        if cap == 0:
            return []
        norm_allowed_fams: set[str] | None = None
        if allowed_families is not None:
            norm_allowed_fams = {str(f or "").strip().lower() for f in allowed_families if str(f or "").strip()}
            if not norm_allowed_fams:
                return []

        route_methods_all: dict[str, set[str]] = {}
        route_params: dict[str, set[str]] = {}
        candidate_templates: set[str] = set()

        def _add_candidate(raw_path: str, method: str = "", display: str = "") -> str | None:
            raw = str(raw_path or "").strip()
            if not raw or is_non_endpoint_source_path(raw) or self._is_port_in_path_noise(raw):
                return None
            tmpl = self._scoped_template(raw)
            if (
                is_non_endpoint_source_path(tmpl)
                or self._is_port_in_path_noise(tmpl)
                or is_os_filesystem_path(tmpl)
                or is_hashed_asset_chunk_path(tmpl)
                or (is_static_asset_url(tmpl) and not _extract_path_embedded_params(tmpl))
                or is_logout_or_destructive_route(tmpl)
            ):
                return None
            candidate_templates.add(tmpl)
            if method:
                route_methods_all.setdefault(tmpl, set()).add(str(method).strip().upper())
            if display and "?" in display:
                q_part = display.split("?", 1)[1]
                for k, _ in parse_qsl(q_part, keep_blank_values=True):
                    if k.strip():
                        route_params.setdefault(tmpl, set()).add(k.strip())
            return tmpl

        for (method, norm_p), display in self.discovered_routes.items():
            _add_candidate(norm_p, method=method, display=display)
        for method, tmpl in self.declared_write_ops:
            _add_candidate(tmpl, method=method)
        for method, tmpl in self.discovered_write_ops:
            _add_candidate(tmpl, method=method)
        for method, tmpl in self.discovered_body_templates:
            _add_candidate(tmpl, method=method)
        for tmpl, pset in self.discovered_params.items():
            clean_t = _add_candidate(tmpl)
            if clean_t is not None and pset:
                route_params.setdefault(clean_t, set()).update(str(p).strip() for p in pset if str(p).strip())
        for tmpl in self.discovered_form_templates:
            _add_candidate(tmpl)
        for tmpl, hset in self.discovered_schema_hints.items():
            if any(str(h).lower().startswith("multipart:") for h in (hset or ())):
                _add_candidate(tmpl)
        for method, tmpl in self.visited_method_templates:
            if tmpl in candidate_templates:
                route_methods_all.setdefault(tmpl, set()).add(str(method).strip().upper())

        non_404_templates = set(self._non_404_templates)
        for ok_p in self.route_2xx_actors:
            non_404_templates.add(self._scoped_template(ok_p))
        for tmpl, pmap in self.param_probes_by_template.items():
            if tmpl in candidate_templates or tmpl in non_404_templates:
                clean_t = _add_candidate(tmpl)
                if clean_t is not None and isinstance(pmap, dict):
                    route_params.setdefault(clean_t, set()).update(
                        str(k).strip() for k in pmap if str(k).strip()
                    )

        scored_entries: list[dict[str, Any]] = []
        for tmpl in sorted(candidate_templates):
            if norm_allowed_fams is not None:
                fam = _extract_route_family(tmpl)
                sub = _extract_api_subfamily(tmpl, fam)
                if fam not in norm_allowed_fams and (sub is None or sub not in norm_allowed_fams):
                    continue

            all_m = route_methods_all.get(tmpl) or set()
            allowed_m = all_m & self.allowed_methods
            if all_m and not allowed_m:
                continue
            if not allowed_m:
                if "GET" in self.allowed_methods:
                    allowed_m = {"GET"}
                elif self.allowed_methods:
                    allowed_m = {sorted(self.allowed_methods)[0]}
                else:
                    continue

            if self.is_route_actively_probed(tmpl, methods=sorted(allowed_m)):
                continue
            if tmpl in self.pruned_spa_routes and tmpl not in self._non_404_templates:
                continue

            ordered_params = _order_params_by_risk(sorted(route_params.get(tmpl) or ()))
            hints = sorted(self.discovered_schema_hints.get(tmpl) or ())
            has_bt = any(t == tmpl for _, t in self.discovered_body_templates)
            risk_score, reason = score_route_input_risk(
                tmpl,
                methods=sorted(allowed_m),
                params=ordered_params,
                schema_hints=hints,
                is_form=(tmpl in self.discovered_form_templates),
                has_body_template=has_bt,
            )
            if risk_score < _HIGH_RISK_SCORE_THRESHOLD:
                continue

            ordered_methods = sorted(
                allowed_m,
                key=lambda m: (0 if m in _MUTATING_HTTP_METHODS else 1, m),
            )
            scored_entries.append({
                "route_template": tmpl,
                "methods": ordered_methods,
                "params": ordered_params,
                "risk_score": risk_score,
                "reason": reason,
            })

        scored_entries.sort(key=lambda item: (-int(item["risk_score"]), str(item["route_template"])))
        return scored_entries[:cap]

    def high_value_frontier(self) -> dict[str, list[str]]:
        """Return remaining high-value frontier items grouped by category."""
        return {
            "unvisited_routes": self.unvisited_routes()[:12],
            "unprobed_params": self.unprobed_params()[:6],
            "untested_cross_actor_objects": self.untested_cross_actor_objects()[:10],
            "untested_write_ops": self.untested_write_ops()[:8],
            "api_parity_untested": self.untested_api_parity()[:6],
            "untested_actors": self.untested_actors()[:6],
        }

    def has_high_value_frontier(self) -> bool:
        """Return True if any high-value route, param depth, cross-actor object, write op, or API parity item remains."""
        frontier = self.high_value_frontier()
        return bool(
            frontier["unvisited_routes"]
            or frontier["unprobed_params"]
            or frontier["untested_cross_actor_objects"]
            or frontier["untested_write_ops"]
            or frontier["api_parity_untested"]
        )

    def _format_compact_schema_hints(self, *, max_routes: int = 2, max_hints: int = 3) -> str:
        """Render compact 400/422 validation schema hints for banner inclusion."""
        if not self.discovered_schema_hints:
            return ""
        items: list[str] = []
        for tmpl, hset in sorted(self.discovered_schema_hints.items()):
            clean = sorted(str(h) for h in hset if str(h))[:max_hints]
            if not clean:
                continue
            items.append(f"{tmpl}({','.join(clean)})")
            if len(items) >= max_routes:
                break
        return f"schema_hints: [{'; '.join(items)}]" if items else ""

    def _format_compact_body_templates(self, *, max_templates: int = 2) -> str:
        """Render compact observed working write-body key summaries for banner inclusion."""
        if not self.discovered_body_templates:
            return ""
        items: list[str] = []
        for (method, tmpl), doc in sorted(self.discovered_body_templates.items()):
            if not isinstance(doc, dict) or not doc:
                continue
            keys = ",".join(str(k) for k in list(doc.keys())[:6])
            items.append(f"{method} {tmpl}{{{keys}}}")
            if len(items) >= max_templates:
                break
        return f"body_templates: [{'; '.join(items)}]" if items else ""

    def _format_error_delta_candidates(self, *, max_items: int = 3) -> str:
        """Render compact 500-delta injection candidates (2xx -> 500) for high-priority verification."""
        if not self.error_delta_params or max_items <= 0:
            return ""
        ordered = sorted(
            self.error_delta_params.items(),
            key=lambda kv: (-int(kv[1].get("count_500") or 1), kv[0]),
        )
        items: list[str] = []
        for (tmpl, pname), info in ordered[:max_items]:
            sample_p = str(info.get("sample_path") or tmpl)
            b_stat = int(info.get("baseline_status") or 200)
            e_stat = int(info.get("error_status") or 500)
            if str(pname).startswith("path:"):
                items.append(f"{sample_p} [{pname}] ({b_stat}->{e_stat}, verify SQLi/SSTI/injection)")
            else:
                items.append(f"{sample_p}?{pname} ({b_stat}->{e_stat}, verify SQLi/SSTI/injection)")
        return f"500-delta injection candidates: {'; '.join(items)}" if items else ""

    def format_frontier_banner(self, *, max_chars: int = 1000) -> str:
        """Render a compact (~1 KB) `[SURFACE FRONTIER]` block for turn state injection."""
        if max_chars <= 0:
            return ""
        frontier = self.high_value_frontier()
        all_routes = self.unvisited_routes()
        all_params = self.unprobed_params()
        all_objs = self.untested_cross_actor_objects()
        all_writes = self.untested_write_ops()

        def _append_compact_intel(base_text: str) -> str:
            result = base_text
            for extra in (self._format_compact_schema_hints(), self._format_compact_body_templates()):
                if extra and len(result) + 3 + len(extra) <= max_chars:
                    result = f"{result} | {extra}"
            return result[:max_chars]

        if not any(
            (
                frontier["unvisited_routes"],
                frontier["unprobed_params"],
                frontier["untested_cross_actor_objects"],
                frontier["untested_write_ops"],
                frontier["api_parity_untested"],
                frontier["untested_actors"],
            )
        ):
            for ed_cap in (3, 1, 0):
                ed_line = self._format_error_delta_candidates(max_items=ed_cap)
                if ed_line:
                    base_with_done = (
                        f"\n[SURFACE FRONTIER] {ed_line} | "
                        "All discovered routes, objects, and allowed write ops covered."
                    )
                    if len(base_with_done) <= max_chars:
                        return _append_compact_intel(base_with_done)
                    base_ed_only = f"\n[SURFACE FRONTIER] {ed_line}"
                    if len(base_ed_only) <= max_chars or ed_cap == 1:
                        return base_ed_only[:max_chars]
            base_done = "\n[SURFACE FRONTIER] All discovered routes, objects, and allowed write ops covered."
            return _append_compact_intel(base_done)

        def _build(
            r_cap: int,
            q_cap: int,
            o_cap: int,
            p_cap: int,
            w_cap: int,
            a_cap: int,
            ed_cap: int = 2,
        ) -> str:
            parts: list[str] = []
            ed_line = self._format_error_delta_candidates(max_items=ed_cap)
            if ed_line:
                parts.append(ed_line)
            if frontier["unvisited_routes"]:
                routes = ", ".join(frontier["unvisited_routes"][:r_cap])
                parts.append(f"unvisited_routes({len(all_routes)}): [{routes}]")
            if frontier["unprobed_params"]:
                qparams = ", ".join(frontier["unprobed_params"][:q_cap])
                parts.append(f"unprobed_params({len(all_params)}): [{qparams}]")
            if frontier["untested_cross_actor_objects"]:
                objs = ", ".join(frontier["untested_cross_actor_objects"][:o_cap])
                parts.append(f"untested_objects({len(all_objs)}): [{objs}]")
            if frontier["api_parity_untested"]:
                parity = ", ".join(frontier["api_parity_untested"][:p_cap])
                parts.append(f"api_parity_untested: [{parity}]")
            if frontier["untested_write_ops"]:
                writes = ", ".join(frontier["untested_write_ops"][:w_cap])
                parts.append(f"untested_writes({len(all_writes)}): [{writes}]")
            if frontier["untested_actors"]:
                acts = ", ".join(frontier["untested_actors"][:a_cap])
                parts.append(f"untested_actors: [{acts}]")
            return "\n[SURFACE FRONTIER] " + " | ".join(parts)

        for caps in (
            (6, 3, 4, 3, 6, 5, 2),
            (3, 2, 2, 3, 3, 3, 2),
            (2, 1, 1, 3, 1, 2, 1),
            (1, 1, 1, 2, 1, 1, 1),
        ):
            candidate = _build(*caps)
            if len(candidate) <= max_chars:
                return _append_compact_intel(candidate)
        return _build(1, 1, 1, 2, 1, 1, 1)[:max_chars]

    def render_frontier_banner(self, *, max_chars: int = 1000) -> str:
        """Render the compact (~1 KB) `[SURFACE FRONTIER]` banner (alias of `format_frontier_banner`)."""
        return self.format_frontier_banner(max_chars=max_chars)

    def to_dict(self) -> dict[str, Any]:
        """Serialize tracker state for checkpoint persistence."""
        payload: dict[str, Any] = {
            "base_url": self.base_url,
            "allowed_methods": sorted(self.allowed_methods),
            "actors": dict(self.actors),
            "exercised_actors": sorted(self.exercised_actors),
            "visited_method_paths": [list(x) for x in sorted(self.visited_method_paths)],
            "visited_method_templates": [list(x) for x in sorted(self.visited_method_templates)],
            "tested_params_by_template": {k: sorted(v) for k, v in self.tested_params_by_template.items()},
            "param_probes_by_template": {
                tmpl: {
                    pname: {
                        "values": sorted(rec.get("values") or ()),
                        "has_special": bool(rec.get("has_special")),
                    }
                    for pname, rec in sorted(pmap.items())
                }
                for tmpl, pmap in sorted(self.param_probes_by_template.items())
            },
            "html_or_form_templates": sorted(self.html_or_form_templates),
            "discovered_form_templates": sorted(self.discovered_form_templates),
            "actively_probed_templates": sorted(self.actively_probed_templates),
            "non_404_templates": sorted(self._non_404_templates),
            "actors_by_template": {k: sorted(v) for k, v in self.actors_by_template.items()},
            "actors_by_path": {k: sorted(v) for k, v in self.actors_by_path.items()},
            "route_2xx_actors": {k: sorted(v) for k, v in sorted(self.route_2xx_actors.items()) if v},
            "soft_deny_routes": {k: sorted(v) for k, v in sorted(self.soft_deny_routes.items()) if v},
            "error_delta_params": [
                [k[0], k[1], dict(v)]
                for k, v in sorted(self.error_delta_params.items())
            ],
            "param_2xx_values": [
                [k[0], k[1], sorted(v)]
                for k, v in sorted(self._param_2xx_values.items())
            ],
            "param_2xx_status": [
                [k[0], k[1], int(v)]
                for k, v in sorted(self._param_2xx_status.items())
            ],
            "param_500_values": [
                [k[0], k[1], sorted(v)]
                for k, v in sorted(self._param_500_values.items())
            ],
            "two_xx_templates": sorted(self._2xx_templates),
            "spa_route_candidates": sorted(self._spa_route_candidates),
            "non_spa_discovered_paths": sorted(self._non_spa_discovered_paths),
            "pruned_spa_routes": sorted(self.pruned_spa_routes),
            "spa_fp_paths": {k: sorted(v) for k, v in sorted(self._spa_fp_paths.items())},
            "suppressed_spa_fingerprints": sorted(self._suppressed_spa_fingerprints),
            "suppressed_spa_fallback_paths": sorted(self.suppressed_spa_fallback_paths),
            "spa_404_prefixes": sorted(self._spa_404_prefixes),
            "spa_shell_prefixes": sorted(self._spa_shell_prefixes),
            "spa_404_templates": sorted(self._spa_404_templates),
            "spa_shell_templates": sorted(self._spa_shell_templates),
            "non_fallback_templates": sorted(self._non_fallback_templates),
            "template_spa_fps": {k: sorted(v) for k, v in sorted(self._template_spa_fps.items())},
            "spa_404_candidate_fallback_seen": bool(self._spa_404_candidate_fallback_seen),
            "discovered_routes": [[k[0], k[1], v] for k, v in sorted(self.discovered_routes.items())],
            "discovered_params": {k: sorted(v) for k, v in self.discovered_params.items()},
            "discovered_objects": {
                k: {
                    "path": v["path"],
                    "template": v["template"],
                    "owner_actor": v.get("owner_actor", ""),
                    "seen_by": sorted(v["seen_by"]),
                    "listed_by": sorted(v.get("listed_by") or ()),
                    "tested_by": sorted(v["tested_by"]),
                    "verified_2xx": bool(v.get("verified_2xx")),
                }
                for k, v in self.discovered_objects.items()
            },
            "collection_listed_objects": {
                k: sorted(v) for k, v in sorted(self.collection_listed_objects.items())
            },
            "pruned_404_objects": sorted(self._pruned_404_objects),
            "discovered_write_ops": [[k[0], k[1], v] for k, v in sorted(self.discovered_write_ops.items())],
            "declared_write_ops": [list(x) for x in sorted(self.declared_write_ops)],
            "tested_write_ops": [list(x) for x in sorted(self.tested_write_ops)],
            "api_prefix_routes": {k: sorted(v) for k, v in sorted(self.api_prefix_routes.items())},
            "ui_resource_families": {
                k: {
                    "concrete_ids": list(v.get("concrete_ids") or []),
                    "collection_2xx": bool(v.get("collection_2xx")),
                    "collection_403": bool(v.get("collection_403")),
                }
                for k, v in sorted(self.ui_resource_families.items())
            },
            "discovered_body_templates": [
                [k[0], k[1], v] for k, v in sorted(self.discovered_body_templates.items())
            ],
            "discovered_schema_hints": {
                k: sorted(v) for k, v in sorted(self.discovered_schema_hints.items()) if v
            },
        }
        if self.in_scope_assets:
            payload["in_scope_assets"] = list(self.in_scope_assets)
        if self.out_of_scope_assets:
            payload["out_of_scope_assets"] = list(self.out_of_scope_assets)
        if self.excluded_paths:
            payload["excluded_paths"] = list(self.excluded_paths)
        return payload

    def load_dict(self, data: dict[str, Any]) -> None:
        """Restore tracker state from a checkpoint dictionary."""
        if not isinstance(data, dict):
            return
        if not self.in_scope_assets and isinstance(data.get("in_scope_assets"), list):
            self.in_scope_assets = tuple(
                str(x).strip() for x in data["in_scope_assets"] if str(x or "").strip()
            )
        if not self.out_of_scope_assets and isinstance(data.get("out_of_scope_assets"), list):
            self.out_of_scope_assets = tuple(
                str(x).strip() for x in data["out_of_scope_assets"] if str(x or "").strip()
            )
        if not self.excluded_paths and isinstance(data.get("excluded_paths"), list):
            self.excluded_paths = tuple(
                str(x).strip() for x in data["excluded_paths"] if str(x or "").strip()
            )
        if self._scope_guard is None and (self.in_scope_assets or self.out_of_scope_assets):
            self._scope_guard = ScopeGuard(
                self.base_url,
                excluded_paths=self.excluded_paths,
                in_scope_assets=self.in_scope_assets,
                out_of_scope_assets=self.out_of_scope_assets,
            )
        self.exercised_actors = set(data.get("exercised_actors") or [])
        self.visited_method_paths = {(str(x[0]), str(x[1])) for x in (data.get("visited_method_paths") or []) if len(x) == 2}
        self.visited_method_templates = {(str(x[0]), str(x[1])) for x in (data.get("visited_method_templates") or []) if len(x) == 2}
        self.tested_params_by_template = {
            str(k): set(v) for k, v in (data.get("tested_params_by_template") or {}).items() if isinstance(v, list)
        }
        self.param_probes_by_template = {}
        for tmpl, pmap in (data.get("param_probes_by_template") or {}).items():
            if isinstance(pmap, dict):
                restored_pmap: dict[str, dict[str, Any]] = {}
                for pname, rec in pmap.items():
                    if isinstance(rec, dict):
                        restored_pmap[str(pname)] = {
                            "values": {str(val) for val in (rec.get("values") or [])},
                            "has_special": bool(rec.get("has_special")),
                        }
                if restored_pmap:
                    self.param_probes_by_template[str(tmpl)] = restored_pmap
        self.html_or_form_templates = {str(x) for x in (data.get("html_or_form_templates") or [])}
        self.discovered_form_templates = {
            str(x)
            for x in (data.get("discovered_form_templates") or [])
            if not is_non_endpoint_source_path(str(x))
        }
        self.actively_probed_templates = {
            str(x)
            for x in (data.get("actively_probed_templates") or [])
            if not is_non_endpoint_source_path(str(x))
        }
        self._non_404_templates = {
            str(x)
            for x in (data.get("non_404_templates") or [])
            if not is_non_endpoint_source_path(str(x))
        }
        self.actors_by_template = {
            str(k): set(v) for k, v in (data.get("actors_by_template") or {}).items() if isinstance(v, list)
        }
        self.actors_by_path = {
            str(k): set(v) for k, v in (data.get("actors_by_path") or {}).items() if isinstance(v, list)
        }
        self.route_2xx_actors = {
            str(k): {str(a) for a in v if str(a)}
            for k, v in (data.get("route_2xx_actors") or {}).items()
            if isinstance(v, list) and not is_non_endpoint_source_path(str(k))
        }
        self.soft_deny_routes = {
            str(k): {str(a) for a in v if str(a)}
            for k, v in (data.get("soft_deny_routes") or {}).items()
            if isinstance(v, list) and not is_non_endpoint_source_path(str(k))
        }
        self.error_delta_params = {}
        for row in (data.get("error_delta_params") or []):
            if isinstance(row, list) and len(row) == 3 and isinstance(row[2], dict):
                e_tmpl = str(row[0] or "").strip()
                e_param = str(row[1] or "").strip()
                if e_tmpl and e_param and len(self.error_delta_params) < _MAX_ERROR_DELTA_PARAMS:
                    self.error_delta_params[(e_tmpl, e_param)] = {
                        "route_template": e_tmpl,
                        "param": e_param,
                        "sample_path": str(row[2].get("sample_path") or e_tmpl),
                        "method": str(row[2].get("method") or "GET").upper(),
                        "baseline_status": int(row[2].get("baseline_status") or 200),
                        "error_status": int(row[2].get("error_status") or 500),
                        "baseline_value": str(row[2].get("baseline_value") or "")[:64],
                        "error_value": str(row[2].get("error_value") or "")[:64],
                        "count_500": max(1, int(row[2].get("count_500") or 1)),
                    }
        self._param_2xx_values = {}
        for row in (data.get("param_2xx_values") or []):
            if isinstance(row, list) and len(row) == 3 and isinstance(row[2], list):
                p_tmpl, p_name = str(row[0] or "").strip(), str(row[1] or "").strip()
                if p_tmpl and p_name and len(self._param_2xx_values) < _MAX_ERROR_DELTA_VALUE_TRACKED:
                    self._param_2xx_values[(p_tmpl, p_name)] = {
                        str(x)[:64] for x in row[2][:_MAX_PARAM_VALUES_TRACKED]
                    }
        self._param_2xx_status = {}
        for row in (data.get("param_2xx_status") or []):
            if isinstance(row, list) and len(row) == 3:
                p_tmpl, p_name = str(row[0] or "").strip(), str(row[1] or "").strip()
                if p_tmpl and p_name and not isinstance(row[2], bool):
                    try:
                        self._param_2xx_status[(p_tmpl, p_name)] = int(row[2])
                    except (TypeError, ValueError):
                        pass
        self._param_500_values = {}
        for row in (data.get("param_500_values") or []):
            if isinstance(row, list) and len(row) == 3 and isinstance(row[2], list):
                p_tmpl, p_name = str(row[0] or "").strip(), str(row[1] or "").strip()
                if p_tmpl and p_name and len(self._param_500_values) < _MAX_ERROR_DELTA_VALUE_TRACKED:
                    self._param_500_values[(p_tmpl, p_name)] = {
                        str(x)[:64] for x in row[2][:_MAX_PARAM_VALUES_TRACKED]
                    }
        self._2xx_templates = {
            str(x) for x in (data.get("two_xx_templates") or []) if str(x)
        }
        self._spa_route_candidates = {
            str(x) for x in (data.get("spa_route_candidates") or []) if str(x)
        }
        self._non_spa_discovered_paths = {
            str(x) for x in (data.get("non_spa_discovered_paths") or []) if str(x)
        }
        self.pruned_spa_routes = {
            str(x) for x in (data.get("pruned_spa_routes") or []) if str(x)
        }
        raw_fp_paths = data.get("spa_fp_paths")
        self._spa_fp_paths = {
            str(k): {str(p) for p in v[:_MAX_SPA_FP_PATHS_PER_BUCKET] if str(p)}
            for k, v in (list(raw_fp_paths.items())[:_MAX_SPA_FP_BUCKETS] if isinstance(raw_fp_paths, dict) else ())
            if isinstance(v, list)
        }
        self._suppressed_spa_fingerprints = {
            str(x) for x in (data.get("suppressed_spa_fingerprints") or []) if str(x)
        }
        self.suppressed_spa_fallback_paths = {
            str(x) for x in (data.get("suppressed_spa_fallback_paths") or []) if str(x)
        }
        self._spa_404_prefixes = {
            str(x) for x in (data.get("spa_404_prefixes") or []) if str(x)
        }
        self._spa_shell_prefixes = {
            str(x) for x in (data.get("spa_shell_prefixes") or []) if str(x)
        }
        self._spa_404_templates = {
            str(x) for x in (data.get("spa_404_templates") or []) if str(x)
        }
        self._spa_shell_templates = {
            str(x) for x in (data.get("spa_shell_templates") or []) if str(x)
        }
        self._non_fallback_templates = {
            str(x) for x in (data.get("non_fallback_templates") or []) if str(x)
        }
        raw_tmpl_fps = data.get("template_spa_fps")
        self._template_spa_fps = {
            str(k): {str(fp) for fp in v[:8] if str(fp)}
            for k, v in (raw_tmpl_fps.items() if isinstance(raw_tmpl_fps, dict) else ())
            if isinstance(v, list)
        }
        self._spa_404_candidate_fallback_seen = bool(data.get("spa_404_candidate_fallback_seen", False))
        self.discovered_routes = {
            (str(x[0]), str(x[1])): str(x[2])
            for x in (data.get("discovered_routes") or [])
            if isinstance(x, list)
            and len(x) == 3
            and not is_non_endpoint_source_path(str(x[1]))
            and not self._is_port_in_path_noise(str(x[1]))
            and not (is_static_asset_url(str(x[1])) and not _extract_path_embedded_params(str(x[1])))
            and not (str(x[0]) == "GET" and str(x[1]) in self.pruned_spa_routes)
        }
        self.discovered_params = {
            str(k): set(v)
            for k, v in (data.get("discovered_params") or {}).items()
            if isinstance(v, list)
            and not is_non_endpoint_source_path(str(k))
            and not self._is_port_in_path_noise(str(k))
        }
        self.discovered_objects = {}
        for k, v in (data.get("discovered_objects") or {}).items():
            if isinstance(v, dict):
                obj_key = str(k)
                obj_path = str(v.get("path") or obj_key)
                if (
                    is_non_endpoint_source_path(obj_key)
                    or is_non_endpoint_source_path(obj_path)
                    or self._is_port_in_path_noise(obj_key)
                    or self._is_port_in_path_noise(obj_path)
                ):
                    continue
                norm_obj = (
                    self._format_scoped_path(obj_path)
                    if obj_path.lower().startswith(("http://", "https://"))
                    else normalize_path(obj_path)
                )
                obj_tmpl = str(v.get("template") or self._scoped_template(norm_obj))
                if (
                    is_non_endpoint_source_path(norm_obj)
                    or is_non_endpoint_source_path(obj_tmpl)
                    or self._is_port_in_path_noise(norm_obj)
                    or "{id}" not in obj_tmpl
                    or "{" in norm_obj
                    or (urlsplit(norm_obj).path or norm_obj).lower().endswith((".js", ".mjs", ".html"))
                ):
                    continue
                self.discovered_objects[obj_key] = {
                    "path": norm_obj if norm_obj else obj_path,
                    "template": obj_tmpl,
                    "owner_actor": str(v.get("owner_actor") or ""),
                    "seen_by": set(v.get("seen_by") or []),
                    "listed_by": set(v.get("listed_by") or []),
                    "tested_by": set(v.get("tested_by") or []),
                    "verified_2xx": bool(v.get("verified_2xx")),
                }
        self.collection_listed_objects = {
            str(k): {str(a) for a in v}
            for k, v in (data.get("collection_listed_objects") or {}).items()
            if isinstance(v, list)
            and not is_non_endpoint_source_path(str(k))
            and not self._is_port_in_path_noise(str(k))
        }
        self._pruned_404_objects = {str(x) for x in (data.get("pruned_404_objects") or [])}
        self.discovered_write_ops = {
            (str(x[0]), str(x[1])): str(x[2])
            for x in (data.get("discovered_write_ops") or [])
            if isinstance(x, list)
            and len(x) == 3
            and not is_non_endpoint_source_path(str(x[1]))
            and not is_non_endpoint_source_path(str(x[2]))
            and not self._is_port_in_path_noise(str(x[1]))
            and not self._is_port_in_path_noise(str(x[2]))
        }
        self.declared_write_ops = {
            (str(x[0]), str(x[1]))
            for x in (data.get("declared_write_ops") or [])
            if isinstance(x, list)
            and len(x) == 2
            and not is_non_endpoint_source_path(str(x[1]))
            and not self._is_port_in_path_noise(str(x[1]))
        }
        self.tested_write_ops = {(str(x[0]), str(x[1])) for x in (data.get("tested_write_ops") or []) if len(x) == 2}

        if isinstance(data.get("api_prefix_routes"), dict):
            self.api_prefix_routes = {}
            for k, v in data["api_prefix_routes"].items():
                if not isinstance(v, list):
                    continue
                cleaned_p = {
                    str(p)
                    for p in v
                    if not is_non_endpoint_source_path(str(p)) and not _is_passive_spec_path(str(p))
                }
                if cleaned_p:
                    self.api_prefix_routes[str(k)] = cleaned_p
        else:
            self.api_prefix_routes = {}
            for _, path in list(self.discovered_routes.keys()) + list(self.visited_method_paths):
                if is_non_endpoint_source_path(path) or _is_passive_spec_path(path):
                    continue
                prefix = _extract_api_prefix(path)
                if prefix:
                    p_str = str(path)
                    if p_str.lower().startswith(("http://", "https://")):
                        parsed_p = urlsplit(p_str)
                        if not self._is_primary_origin(parsed_p.scheme, parsed_p.netloc):
                            prefix_key = f"{parsed_p.scheme.lower()}://{parsed_p.netloc.lower()}{prefix}"
                            self.api_prefix_routes.setdefault(prefix_key, set()).add(
                                self._format_scoped_path(p_str)
                            )
                            continue
                    self.api_prefix_routes.setdefault(prefix, set()).add(normalize_path(path))

        if isinstance(data.get("ui_resource_families"), dict):
            self.ui_resource_families = {}
            for k, v in data["ui_resource_families"].items():
                res_k = str(k)
                if (
                    isinstance(v, dict)
                    and _NUMERIC_SLUG_CATEGORY_RE.match(res_k) is None
                    and not _is_passive_spec_path(f"/{res_k}")
                ):
                    self.ui_resource_families[res_k] = {
                        "concrete_ids": [str(cid) for cid in (v.get("concrete_ids") or []) if str(cid)],
                        "collection_2xx": bool(v.get("collection_2xx")),
                        "collection_403": bool(v.get("collection_403")),
                    }
        else:
            self.ui_resource_families = {}
            for norm_p in self.discovered_objects:
                self._observe_parity_path(norm_p, discovered=True)
            for _, norm_p in self.discovered_routes:
                info = _extract_ui_resource_info(norm_p)
                if info is not None and info[2]:
                    self._observe_parity_path(norm_p, discovered=True)
        self._sync_ui_api_concrete_siblings()
        self.discovered_body_templates = {}
        for row in (data.get("discovered_body_templates") or []):
            if isinstance(row, list) and len(row) == 3 and isinstance(row[2], dict):
                m_up = str(row[0] or "").strip().upper()
                tmpl_key = str(row[1] or "").strip()
                if (
                    m_up
                    and tmpl_key
                    and not is_non_endpoint_source_path(tmpl_key)
                    and len(self.discovered_body_templates) < _MAX_BODY_TEMPLATES
                ):
                    sanitized = _sanitize_json_template(row[2])
                    if isinstance(sanitized, dict) and sanitized:
                        fitted = _fit_body_template_budget(sanitized, max_chars=_MAX_BODY_TEMPLATE_CHARS)
                        if fitted:
                            self.discovered_body_templates[(m_up, tmpl_key)] = fitted
        self.discovered_schema_hints = {}
        for tmpl_key, raw_hints in (data.get("discovered_schema_hints") or {}).items():
            if not isinstance(raw_hints, list) or is_non_endpoint_source_path(str(tmpl_key)):
                continue
            cleaned = {str(h).strip() for h in raw_hints if str(h).strip()}
            if cleaned and len(self.discovered_schema_hints) < _MAX_SCHEMA_HINT_TEMPLATES:
                self.discovered_schema_hints[str(tmpl_key)] = set(sorted(cleaned)[:_MAX_SCHEMA_HINTS_PER_TEMPLATE])

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        base_url: str = "",
        allowed_methods: Sequence[str] | None = None,
        actor_summaries: Sequence[dict[str, str]] | None = None,
        in_scope_assets: Sequence[str] | None = None,
        out_of_scope_assets: Sequence[str] | None = None,
        excluded_paths: Sequence[str] | None = None,
    ) -> SurfaceFrontierTracker:
        """Instantiate and restore a `SurfaceFrontierTracker` from a checkpoint dictionary."""
        raw = data if isinstance(data, dict) else {}
        eff_base = base_url or str(raw.get("base_url") or "http://localhost")
        raw_methods = raw.get("allowed_methods")
        eff_methods: Sequence[str] = (
            allowed_methods
            if allowed_methods is not None
            else ([str(m) for m in raw_methods] if isinstance(raw_methods, list) else ("GET", "HEAD"))
        )
        raw_actors = raw.get("actors")
        eff_actors: Sequence[dict[str, str]] = (
            actor_summaries
            if actor_summaries is not None
            else ([v for v in raw_actors.values() if isinstance(v, dict)] if isinstance(raw_actors, dict) else ())
        )
        raw_in_scope = raw.get("in_scope_assets")
        eff_in_scope: Sequence[str] = (
            in_scope_assets
            if in_scope_assets is not None
            else ([str(x) for x in raw_in_scope if str(x or "").strip()] if isinstance(raw_in_scope, list) else ())
        )
        raw_out_scope = raw.get("out_of_scope_assets")
        eff_out_scope: Sequence[str] = (
            out_of_scope_assets
            if out_of_scope_assets is not None
            else ([str(x) for x in raw_out_scope if str(x or "").strip()] if isinstance(raw_out_scope, list) else ())
        )
        raw_excl = raw.get("excluded_paths")
        eff_excl: Sequence[str] = (
            excluded_paths
            if excluded_paths is not None
            else ([str(x) for x in raw_excl if str(x or "").strip()] if isinstance(raw_excl, list) else ())
        )
        tracker = cls(
            base_url=eff_base,
            allowed_methods=eff_methods,
            actor_summaries=eff_actors,
            in_scope_assets=eff_in_scope,
            out_of_scope_assets=eff_out_scope,
            excluded_paths=eff_excl,
        )
        tracker.load_dict(raw)
        return tracker
