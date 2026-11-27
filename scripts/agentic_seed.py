"""Zero-runtime-overhead offline seed surface importer and optional tech-hints helper.

Purely local offline parsing (0 network calls, zero legacy engine imports) that
converts operator-supplied proxy/HAR/scanner/URL artifacts into strictly
scope-validated, secret-stripped surface payloads ingestible by
`SurfaceFrontierTracker.ingest_surface`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import shlex
import stat
import sys
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit
import xml.etree.ElementTree as ET

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_REPO_ROOT = _SCRIPTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_http import is_static_asset_url  # noqa: E402
from agentic_surface import (  # noqa: E402
    SurfaceFrontierTracker,
    _fit_body_template_budget,
    _sanitize_json_template,
    is_id_segment,
    is_non_endpoint_source_path,
    route_template_of,
)
from kryon_core.surface.extract import is_hashed_asset_chunk_path  # noqa: E402
from kryon_core.surface.normalize import is_os_filesystem_path  # noqa: E402
from kryon_core.surface.openapi import LocalSchema  # noqa: E402
from target_bootstrap import ScopeGuard, normalize_path  # noqa: E402

MAX_SEED_FILE_BYTES = 10 * 1024 * 1024  # 10 MB hard cap per seed file
_MAX_PARAMS_PER_ROUTE = 32
_MAX_QUERY_FIELDS = 128
_MAX_APP_HEADERS = 24
_MAX_APP_HEADER_VALUE_CHARS = 256

_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_XML_XXE_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_XML_ENTITY_RE = re.compile(r"<!\s*ENTITY\b", re.IGNORECASE)
_BURP_ROOT_TAG_RE = re.compile(r"<items?\b", re.IGNORECASE)
_BURP_RESPONSE_CDATA_RE = re.compile(
    r"<response\b[^>]*>\s*<!\[CDATA\[.*?\]\]>\s*</response>",
    re.DOTALL | re.IGNORECASE,
)
_BURP_RESPONSE_ELEM_RE = re.compile(
    r"<response\b[^>]*>.*?</response>",
    re.DOTALL | re.IGNORECASE,
)
_HTML_DOCTYPE_RE = re.compile(r"<!\s*DOCTYPE\s+html\b", re.IGNORECASE)
_OPENAPI_YAML_HEADER_RE = re.compile(r"(?m)^\s*(?:openapi|swagger)\s*:")
_OPENAPI_YAML_PATHS_RE = re.compile(r"(?m)^\s*paths\s*:")
_CURL_LINE_RE = re.compile(r"^curl(?:\s+|$)", re.IGNORECASE)
_POSTMAN_VAR_RE = re.compile(r"\{\{\s*([^{}\s]+)\s*\}\}")
_LEADING_POSTMAN_VAR_RE = re.compile(r"^\{\{\s*([^{}\s]+)\s*\}\}(?=$|[/?#])")
_JWT_LIKE_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")
_KNOWN_SECRET_VAL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:ghp_[A-Za-z0-9]{4,}|sk_live_[A-Za-z0-9]{4,}|xox[A-Za-z0-9-]{4,}|AIza[0-9A-Za-z_-]{6,})"
)
_EMAIL_HEADER_VAL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_MAX_OPENAPI_YAML_NODES = 25_000
_MAX_OPENAPI_YAML_DEPTH = 64
_SAFE_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")
_NON_ALNUM_SEP_RE = re.compile(r"[^a-z0-9]+")

_CANONICAL_APP_HEADER_NAMES: dict[str, str] = {
    "content-type": "Content-Type",
    "x-storefront": "X-Storefront",
    "x-api-version": "X-Api-Version",
    "x-requested-with": "X-Requested-With",
    "x-apollo-operation-name": "X-Apollo-Operation-Name",
    "x-tenant-id": "X-Tenant-Id",
    "x-client-version": "X-Client-Version",
    "x-platform": "X-Platform",
    "x-channel": "X-Channel",
    "x-locale": "X-Locale",
    "x-currency": "X-Currency",
    "x-graphql-client": "X-GraphQL-Client",
}
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
    "x-signature",
    "x-hmac-signature",
    "x-amz-security-token",
    "x-amz-credential",
    "x-goog-api-key",
    "ocp-apim-subscription-key",
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
    "accept",
    "accept-charset",
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
    "date",
    "from",
    "via",
    "warning",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    # Dynamic tracing noise
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
})
_STRIPPED_HEADER_PREFIXES: tuple[str, ...] = ("sec-", "x-b3-", ":", "cf-", "x-amz-")
_SECRET_HEADER_TOKENS: frozenset[str] = frozenset({
    "auth",
    "authorization",
    "token",
    "secret",
    "password",
    "passwd",
    "pass",
    "pwd",
    "cookie",
    "jwt",
    "bearer",
    "apikey",
    "api_key",
    "credential",
    "credentials",
    "private",
    "private_key",
    "signature",
    "hmac",
    "csrf",
    "xsrf",
    "session",
    "session_id",
    "key",
})
_SECRET_HEADER_SUBSTRINGS: tuple[str, ...] = (
    "auth",
    "jwt",
    "bearer",
    "signature",
    "credential",
    "hmac",
    "session",
    "csrf",
    "xsrf",
    "private",
    "secret",
    "token",
    "key",
    "pass",
    "cookie",
    "apikey",
    "api_key",
    "passwd",
    "password",
)
_SECRET_TEMPLATE_KEY_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "apikey",
    "api_key",
    "csrf",
    "xsrf",
    "jwt",
    "bearer",
    "private_key",
    "client_secret",
    "credential",
    "session_id",
    "pin",
    "cvv",
    "ssn",
)
_CURL_DISCARD_ARG_FLAGS: frozenset[str] = frozenset({
    "-b",
    "--cookie",
    "-c",
    "--cookie-jar",
    "-u",
    "--user",
    "--proxy-user",
    "-U",
    "--oauth2-bearer",
    "--aws-sigv4",
    "-A",
    "--user-agent",
    "-e",
    "--referer",
    "-o",
    "--output",
    "-x",
    "--proxy",
    "-m",
    "--max-time",
    "--connect-timeout",
    "-w",
    "--write-out",
    "--resolve",
    "--cacert",
    "--cert",
    "--key",
    "--interface",
    "--ciphers",
    "--max-redirs",
    "--retry",
})
_CURL_DATA_FLAGS: frozenset[str] = frozenset({
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-ascii",
    "--data-urlencode",
})
_CURL_FORM_FLAGS: frozenset[str] = frozenset({"-F", "--form", "--form-string"})
_MULTIPART_FILENAME_RE = re.compile(r"(?:^|[;\s])filename\*?\s*=", re.IGNORECASE)
_MULTIPART_LINE_RE = re.compile(r"Content-Disposition\s*:\s*([^\r\n]+)", re.IGNORECASE)

_SAFE_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]$]{1,64}$")
_SAFE_PATH_PARAM_MARKER_RE = re.compile(r"^path:[A-Za-z][A-Za-z0-9_.\-]{0,48}=?$")
_PARAM_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_METHOD_PATH_KEY_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/\S*)$",
    re.IGNORECASE,
)
_METHOD_URL_LINE_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)$",
    re.IGNORECASE,
)
_MULTIPART_NAME_RE = re.compile(
    r'Content-Disposition\s*:[^\r\n]*?\bname\s*=\s*"([^"\r\n]{1,64})"',
    re.IGNORECASE,
)
_REQUEST_LINE_METHOD_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+",
    re.IGNORECASE,
)
_SCHEMELESS_HOST_RE = re.compile(
    r"^(?:(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,})(?::\d{1,5})?$",
    re.IGNORECASE,
)
_API_PATH_RE = re.compile(
    r"^/(?:(?:ajax[-_]?)?api(?:/(?:v?\d+(?:\.\d+)?))?|v\d+(?:\.\d+)?|rest|rpc|graphql)(?:/|$)"
    r"|/(?:ajax[-_]?)?api(?:/(?:v?\d+(?:\.\d+)?))?/",
    re.IGNORECASE,
)
_HIGH_RISK_PARAM_EXACT = frozenset({
    "file",
    "url",
    "redirect",
    "path",
    "upload",
    "download",
    "callback",
    "dest",
    "target",
    "next",
})
_HIGH_RISK_PARAM_SUBSTRINGS = (
    "file",
    "url",
    "redirect",
    "upload",
    "download",
    "callback",
)
_GENERIC_SEED_TOP_KEYS = frozenset({
    "schema",
    "links",
    "forms",
    "routes",
    "endpoints",
    "body_templates",
    "multipart_schemas",
    "ws_endpoints",
    "discovery_hints",
})
_HIGH_SIGNAL_KEYWORDS = (
    "admin",
    "internal",
    "debug",
    "config",
    "export",
    "import",
    "upload",
    "download",
    "transfer",
    "payment",
    "billing",
    "invoice",
    "order",
    "account",
    "user",
    "profile",
    "role",
    "permission",
    "token",
    "oauth",
    "webhook",
    "search",
    "report",
    "settings",
    "graphql",
)
_LOW_SIGNAL_EXACT_PATHS = frozenset({"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"})
_NON_HINT_STATIC_ASSET_EXTS: tuple[str, ...] = (
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".mp3",
    ".webm",
)

_TECH_TAG_ALIASES: dict[str, str] = {
    "next": "nextjs",
    "nextjs": "nextjs",
    "spring": "spring",
    "springboot": "spring",
    "java": "spring",
    "tomcat": "spring",
    "django": "django",
    "fastapi": "fastapi",
    "starlette": "fastapi",
    "flask": "flask",
    "rails": "rails",
    "rubyonrails": "rails",
    "ruby": "rails",
    "graphql": "graphql",
    "apollo": "graphql",
    "express": "express",
    "expressjs": "express",
    "node": "node",
    "nodejs": "node",
    "nestjs": "express",
    "laravel": "laravel",
    "php": "php",
    "wordpress": "wordpress",
    "wp": "wordpress",
    "nginx": "nginx",
    "apache": "apache",
    "dotnet": "dotnet",
    "aspnet": "dotnet",
    "iis": "iis",
    "go": "go",
    "golang": "go",
    "swagger": "openapi",
    "openapi": "openapi",
}

_BUILTIN_TECH_HINTS: dict[str, tuple[str, ...]] = {
    "nextjs": (
        "/api/auth/session",
        "/api/auth/providers",
        "/api/health",
        "/api/trpc",
        "/_next/data",
        "/sitemap.xml",
        "/robots.txt",
    ),
    "django": (
        "/admin",
        "/api",
        "/api/schema",
        "/graphql",
        "/accounts/login",
        "/__debug__",
        "/health",
        "/sitemap.xml",
    ),
    "spring": (
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/mappings",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/api",
        "/health",
    ),
    "fastapi": (
        "/openapi.json",
        "/docs",
        "/redoc",
        "/api/v1",
        "/health",
        "/metrics",
    ),
    "flask": (
        "/api",
        "/api/v1",
        "/health",
        "/status",
        "/console",
        "/debug",
        "/metrics",
    ),
    "rails": (
        "/rails/info/routes",
        "/rails/info",
        "/admin",
        "/api",
        "/api/v1",
        "/graphql",
        "/sidekiq",
        "/health",
    ),
    "graphql": (
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graphiql",
        "/playground",
        "/altair",
    ),
    "express": (
        "/api",
        "/api/v1",
        "/api-docs",
        "/swagger.json",
        "/graphql",
        "/health",
        "/status",
        "/metrics",
    ),
    "node": (
        "/api",
        "/api/v1",
        "/graphql",
        "/health",
        "/status",
        "/metrics",
        "/debug",
        "/package.json",
    ),
    "laravel": (
        "/api",
        "/sanctum/csrf-cookie",
        "/telescope",
        "/horizon",
        "/admin",
        "/health",
        "/storage",
    ),
    "php": (
        "/api",
        "/admin",
        "/info.php",
        "/phpinfo.php",
        "/phpmyadmin",
        "/adminer.php",
        "/config.php",
    ),
    "wordpress": (
        "/wp-json",
        "/wp-json/wp/v2/users",
        "/wp-admin",
        "/wp-login.php",
        "/xmlrpc.php",
        "/readme.html",
    ),
    "nginx": (
        "/files",
        "/uploads",
        "/download",
        "/export",
        "/backup",
        "/stub_status",
        "/nginx_status",
    ),
    "apache": (
        "/server-status",
        "/server-info",
        "/cgi-bin",
        "/uploads",
        "/webdav",
        "/manual",
    ),
    "dotnet": (
        "/swagger",
        "/swagger/v1/swagger.json",
        "/api",
        "/health",
        "/elmah.axd",
        "/trace.axd",
        "/web.config",
    ),
    "iis": (
        "/trace.axd",
        "/elmah.axd",
        "/web.config",
        "/admin",
        "/api",
        "/owa",
    ),
    "go": (
        "/debug/pprof",
        "/metrics",
        "/health",
        "/healthz",
        "/api",
        "/status",
    ),
    "openapi": (
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/api-docs",
        "/docs",
        "/swagger-ui.html",
    ),
}

_LOW_VALUE_TECH_HINT_SEGMENTS = frozenset({
    "/css",
    "/js",
    "/images",
    "/img",
    "/fonts",
    "/static",
    "/assets",
})


@dataclass
class _CandidateRoute:
    method: str
    url: str
    params: list[str] = field(default_factory=list)
    is_form: bool = False
    status: int | None = None
    body_template: dict[str, Any] | None = None
    multipart_schema: dict[str, list[str]] | None = None
    app_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class _AcceptedRoute:
    method: str
    path: str
    params: list[str] = field(default_factory=list)
    is_form: bool = False
    best_status: int | None = None
    first_seen: int = 0
    body_template: dict[str, Any] | None = None
    multipart_schema: dict[str, list[str]] | None = None


def _has_control_chars(text: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _to_snake_tokens(name: str) -> tuple[str, tuple[str, ...]]:
    split_camel = _CAMEL_BOUNDARY_RE.sub(r"\1_\2", str(name or "").strip())
    snake = _NON_ALNUM_SEP_RE.sub("_", split_camel.lower()).strip("_")
    tokens = tuple(tok for tok in snake.split("_") if tok)
    return snake, tokens


def _is_secret_or_stripped_header_name(header_name: str) -> bool:
    low = header_name.strip().lower()
    if not low or not _SAFE_HEADER_NAME_RE.fullmatch(header_name.strip()):
        return True
    if low in _STRIPPED_EXACT_HEADERS:
        return True
    if any(low.startswith(prefix) for prefix in _STRIPPED_HEADER_PREFIXES):
        return True
    if low == "content-type":
        return False
    snake, tokens = _to_snake_tokens(low)
    if snake in _SECRET_HEADER_TOKENS or any(tok in _SECRET_HEADER_TOKENS for tok in tokens):
        return True
    return any(sub in snake for sub in _SECRET_HEADER_SUBSTRINGS)


def _is_secret_header_value(value: str, *, header_name_low: str = "") -> bool:
    stripped = value.strip()
    if not stripped or _has_control_chars(stripped) or len(stripped) > _MAX_APP_HEADER_VALUE_CHARS:
        return True
    low = stripped.lower()
    if "<redacted" in low:
        return True
    if (
        low.startswith(("bearer ", "basic ", "digest ", "token ", "aws4-hmac-sha256"))
        or "aws4-hmac-sha256" in low
        or "-----begin " in low
        or "-----end " in low
    ):
        return True
    if (
        _JWT_LIKE_RE.search(stripped)
        or _AWS_KEY_RE.search(stripped)
        or _KNOWN_SECRET_VAL_RE.search(stripped)
        or _EMAIL_HEADER_VAL_RE.search(stripped)
    ):
        return True
    if header_name_low != "content-type" and ";" in stripped and "=" in stripped:
        return True
    return False


def _canonical_app_header_name(name: str) -> str:
    clean = name.strip()
    low = clean.lower()
    if low in _CANONICAL_APP_HEADER_NAMES:
        return _CANONICAL_APP_HEADER_NAMES[low]
    return clean


def _extract_safe_app_headers(raw_headers: Any) -> dict[str, str]:
    """Extract strictly non-secret, non-boilerplate application headers from list/dict/pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(raw_headers, dict):
        for k, v in raw_headers.items():
            if isinstance(k, str) and v is not None:
                pairs.append((k.strip(), str(v).strip()))
    elif isinstance(raw_headers, (list, tuple)):
        for item in raw_headers:
            if isinstance(item, dict):
                if item.get("disabled"):
                    continue
                name = item.get("name") or item.get("key")
                val = item.get("value")
                if isinstance(name, str) and val is not None:
                    pairs.append((name.strip(), str(val).strip()))
            elif isinstance(item, (list, tuple)) and len(item) == 2:
                k, v = item
                if isinstance(k, str) and v is not None:
                    pairs.append((k.strip(), str(v).strip()))
            elif isinstance(item, str) and ":" in item:
                k, v = item.split(":", 1)
                pairs.append((k.strip(), v.strip()))

    cleaned: dict[str, str] = {}
    for raw_name, raw_val in pairs:
        if not raw_name or _has_control_chars(raw_name) or len(raw_name) > 128:
            continue
        low = raw_name.lower()
        if _is_secret_or_stripped_header_name(raw_name):
            continue
        val = raw_val
        if low == "content-type":
            media = val.split(";", 1)[0].strip().lower()
            if not media:
                continue
            val = media
        if _is_secret_header_value(val, header_name_low=low):
            continue
        canon_name = _canonical_app_header_name(raw_name)
        for existing in [k for k in cleaned if k.lower() == low and k != canon_name]:
            cleaned.pop(existing, None)
        cleaned[canon_name] = val[:_MAX_APP_HEADER_VALUE_CHARS]
        if len(cleaned) >= _MAX_APP_HEADERS:
            break
    return cleaned


def _merge_app_headers(target: dict[str, str], incoming: dict[str, str]) -> None:
    if not incoming:
        return
    sanitized = _extract_safe_app_headers(incoming)
    existing_low = {k.lower(): k for k in target}
    for name, val in sanitized.items():
        low = name.lower()
        if low in existing_low:
            continue
        if len(target) >= _MAX_APP_HEADERS:
            break
        target[name] = val
        existing_low[low] = name


def _is_sensitive_template_key(key: str) -> bool:
    snake, tokens = _to_snake_tokens(key)
    if not snake:
        return False
    if snake in _SECRET_HEADER_TOKENS or any(tok in _SECRET_HEADER_TOKENS for tok in tokens):
        return True
    return any(sub in snake for sub in _SECRET_TEMPLATE_KEY_SUBSTRINGS)


def _redact_template_obj(obj: Any, *, depth: int = 0) -> Any:
    """Redact secret keys and credential-like scalar values before template sanitization."""
    if depth > 6:
        return {} if isinstance(obj, dict) else ([] if isinstance(obj, list) else "<redacted>")
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in list(obj.items())[:32]:
            ks = str(k or "").strip()[:64]
            if not ks:
                continue
            if _is_sensitive_template_key(ks):
                out[ks] = "<redacted>"
            else:
                out[ks] = _redact_template_obj(v, depth=depth + 1)
        return out
    if isinstance(obj, list):
        return [_redact_template_obj(item, depth=depth + 1) for item in obj[:6]]
    if isinstance(obj, str):
        stripped = obj.strip()
        low = stripped.lower()
        if (
            "<redacted" in low
            or low.startswith(("bearer ", "basic ", "digest ", "token ", "aws4-hmac-sha256"))
            or "aws4-hmac-sha256" in low
            or "-----begin " in low
            or "-----end " in low
            or _JWT_LIKE_RE.search(stripped)
            or _AWS_KEY_RE.search(stripped)
            or _KNOWN_SECRET_VAL_RE.search(stripped)
        ):
            return "<redacted>"
        return obj
    return obj


def _read_seed_file(path: Path | str, *, max_bytes: int = MAX_SEED_FILE_BYTES) -> str:
    """Safely read a regular non-symlink local seed file with a hard byte cap."""
    if path is None or not str(path).strip():
        raise ValueError("seed file path is required")
    raw_path = Path(path).expanduser()
    try:
        st = raw_path.lstat()
    except OSError as exc:
        raise ValueError(f"seed file is missing or unreadable: {raw_path}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ValueError(f"seed file must not be a symlink: {raw_path}")
    if not stat.S_ISREG(st.st_mode):
        raise ValueError(f"seed file must be a regular file: {raw_path}")
    if st.st_size > max_bytes:
        raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")

    open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(raw_path, open_flags)
    except OSError as exc:
        raise ValueError(f"failed to open seed file {raw_path}: {exc}") from exc

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode):
            raise ValueError(f"seed file must be a regular file: {raw_path}")
        if fd_stat.st_size > max_bytes:
            raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            raw_bytes = fh.read(max_bytes + 1)
    except ValueError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        raise ValueError(f"failed to read seed file {raw_path}: {exc}") from exc

    if len(raw_bytes) > max_bytes:
        raise ValueError(f"seed file exceeds maximum size of {max_bytes} bytes: {raw_path}")
    text = raw_bytes.decode("utf-8", errors="replace")
    return text.lstrip("\ufeff")


def _normalize_method(raw: Any, default: str = "GET") -> str:
    cleaned = str(raw or "").strip().upper()
    if cleaned in _VALID_HTTP_METHODS:
        return cleaned
    return default


def _coerce_status(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    return val if 100 <= val <= 599 else None


def _status_priority(status: int | None) -> int:
    if status is None:
        return 0
    if 200 <= status < 300 or status in {401, 403}:
        return 6
    if 300 <= status < 400 or status in {400, 405, 422}:
        return 3
    if status in {404, 410}:
        return -10
    return -2


def _sanitize_param_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name:
        return ""
    if _SAFE_PARAM_NAME_RE.fullmatch(name) or _SAFE_PATH_PARAM_MARKER_RE.fullmatch(name):
        return name
    return ""


def _sanitize_multipart_schema(raw: Any) -> dict[str, list[str]] | None:
    """Sanitize a multipart schema dict to store only sorted field and file parameter names."""
    if not isinstance(raw, dict):
        return None

    def _clean_seq(val: Any) -> list[str]:
        if not isinstance(val, (list, tuple, set)):
            return []
        names: list[str] = []
        seen: set[str] = set()
        for item in val:
            cand = item.get("name") if isinstance(item, dict) else (item if isinstance(item, str) else "")
            clean = _sanitize_param_name(cand)
            if clean and clean not in seen and len(names) < _MAX_PARAMS_PER_ROUTE:
                seen.add(clean)
                names.append(clean)
        return sorted(names)

    fields = _clean_seq(raw.get("fields"))
    files = _clean_seq(raw.get("files"))
    if not fields and not files:
        return None
    return {"fields": fields, "files": files}


def _sanitize_seed_body_template(raw: Any) -> dict[str, Any] | None:
    """Sanitize, secret-redact, and size-cap a JSON body template dict from seed data."""
    if not isinstance(raw, dict) or not raw:
        return None
    redacted = _redact_template_obj(raw)
    if not isinstance(redacted, dict) or not redacted:
        return None
    sanitized = _sanitize_json_template(redacted)
    if not isinstance(sanitized, dict) or not sanitized:
        return None
    fitted = _fit_body_template_budget(sanitized)
    return fitted if isinstance(fitted, dict) and fitted else None


def _extract_template_param_names(doc: Any, *, depth: int = 0) -> list[str]:
    """Extract sanitized top-level and nested/leaf JSON key names from a body template (never values)."""
    if depth > 4:
        return []
    out: list[str] = []
    seen: set[str] = set()

    def _add(name: Any) -> None:
        clean = _sanitize_param_name(name)
        if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_ROUTE:
            seen.add(clean)
            out.append(clean)

    if isinstance(doc, dict):
        for k, v in doc.items():
            _add(k)
            if isinstance(v, (dict, list)) and len(out) < _MAX_PARAMS_PER_ROUTE:
                for sub in _extract_template_param_names(v, depth=depth + 1):
                    _add(sub)
    elif isinstance(doc, list):
        for elem in doc[:4]:
            if isinstance(elem, (dict, list)) and len(out) < _MAX_PARAMS_PER_ROUTE:
                for sub in _extract_template_param_names(elem, depth=depth + 1):
                    _add(sub)
    return out


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


def _merge_multipart_schemas(
    existing: dict[str, list[str]] | None,
    incoming: dict[str, list[str]] | None,
) -> dict[str, list[str]] | None:
    if incoming is None:
        return existing
    if existing is None:
        return incoming
    fields = sorted(set(existing.get("fields") or ()) | set(incoming.get("fields") or ()))[:_MAX_PARAMS_PER_ROUTE]
    files = sorted(set(existing.get("files") or ()) | set(incoming.get("files") or ()))[:_MAX_PARAMS_PER_ROUTE]
    if not fields and not files:
        return None
    return {"fields": fields, "files": files}


def _parse_method_url_key(key: Any) -> tuple[str, str] | None:
    if not isinstance(key, str):
        return None
    match = _METHOD_URL_LINE_RE.fullmatch(key.strip())
    if not match:
        return None
    return match.group(1).upper(), match.group(2)


def _normalize_ws_endpoint(raw_item: Any, guard: ScopeGuard) -> tuple[dict[str, str] | None, str]:
    """Validate a WebSocket endpoint against `ScopeGuard` and strip query values."""
    raw_url = ""
    if isinstance(raw_item, str):
        raw_url = raw_item.strip()
    elif isinstance(raw_item, dict):
        raw_url = str(raw_item.get("url") or raw_item.get("path") or "").strip()
    if not raw_url:
        return None, ""

    base_parsed = urlsplit(guard.base_origin)
    base_scheme = base_parsed.scheme.lower()
    ws_scheme = "wss" if base_scheme == "https" else "ws"

    low = raw_url.lower()
    if low.startswith("ws://"):
        if base_scheme != "http" and not guard.is_multi_origin:
            return None, "scope"
        http_cand = "http://" + raw_url[5:]
        ws_scheme = "ws"
    elif low.startswith("wss://"):
        if base_scheme != "https" and not guard.is_multi_origin:
            return None, "scope"
        http_cand = "https://" + raw_url[6:]
        ws_scheme = "wss"
    else:
        http_cand = raw_url

    try:
        guard.check_url(http_cand)
    except ValueError:
        return None, "scope"

    resolved = urljoin(guard.base_origin, http_cand)
    parsed = urlsplit(resolved)
    try:
        norm_path = normalize_path(parsed.path or "/")
    except ValueError:
        return None, "scope"

    if is_static_asset_url(norm_path) or is_non_endpoint_source_path(norm_path):
        return None, "static"

    return {"url": f"{ws_scheme}://{parsed.netloc}{norm_path}", "path": norm_path}, ""


def _scoped_route_template(route_target: str) -> str:
    """Normalize ``route_target`` into a template while preserving explicit ``scheme://netloc`` sibling prefixes."""
    raw = str(route_target or "").strip()
    if raw.lower().startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if parsed.netloc:
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{route_template_of(parsed.path or '/')}"
    return route_template_of(raw)


def _has_high_risk_param(params: Sequence[str]) -> bool:
    """Return True if any parameter name suggests file, URL, upload/download, redirect, or path input."""
    for raw_p in params:
        p_low = str(raw_p or "").strip().lower()
        if not p_low:
            continue
        if p_low.startswith("path:"):
            return True
        if p_low in _HIGH_RISK_PARAM_EXACT:
            return True
        if any(sub in p_low for sub in _HIGH_RISK_PARAM_SUBSTRINGS):
            return True
        tokens = [tok for tok in _PARAM_TOKEN_SPLIT_RE.split(p_low) if tok]
        if any(tok in _HIGH_RISK_PARAM_EXACT for tok in tokens):
            return True
    return False


def _extract_param_names(raw: Any) -> list[str]:
    """Extract sanitized parameter/field names only (never values)."""
    out: list[str] = []
    seen: set[str] = set()

    def _add(candidate: Any) -> None:
        clean = _sanitize_param_name(candidate)
        if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_ROUTE:
            seen.add(clean)
            out.append(clean)

    if isinstance(raw, str):
        if "=" in raw or "&" in raw:
            for k, _ in parse_qsl(raw, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS):
                _add(k)
        else:
            _add(raw)
    elif isinstance(raw, dict):
        for k in raw:
            _add(k)
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str):
                _add(item)
            elif isinstance(item, dict):
                _add(item.get("name") or item.get("param") or item.get("key") or item.get("field"))
    return out


def _extract_body_field_names(body_text: str, mime_type: str = "") -> list[str]:
    """Extract JSON/form/multipart field NAMES from a request body (never values)."""
    if not isinstance(body_text, str):
        return []
    raw = body_text.strip()
    if not raw:
        return []
    ctype = str(mime_type or "").split(";", 1)[0].strip().lower()

    if "json" in ctype or raw.startswith(("{", "[")):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return _extract_param_names(list(parsed.keys()))
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            return _extract_param_names(list(parsed[0].keys()))
        if "json" in ctype:
            return []

    if "multipart/form-data" in ctype or "Content-Disposition:" in raw:
        names = _MULTIPART_NAME_RE.findall(raw)
        if names:
            return _extract_param_names(names)
        if "multipart/form-data" in ctype:
            return []

    if "x-www-form-urlencoded" in ctype or ("=" in raw and not raw.startswith(("<", "{", "["))):
        pairs = parse_qsl(raw, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS)
        return _extract_param_names([k for k, _ in pairs])

    return []


def _parse_method_path_key(key: Any) -> tuple[str, str] | None:
    if not isinstance(key, str):
        return None
    match = _METHOD_PATH_KEY_RE.fullmatch(key.strip())
    if not match:
        return None
    return match.group(1).upper(), match.group(2)


def _resolve_host_and_path(host_hint: str, path_or_url: str, guard: ScopeGuard) -> str:
    """Attach an explicit host hint to a relative path so ScopeGuard enforces exact origin."""
    raw_path = str(path_or_url or "").strip()
    if not raw_path:
        return ""
    if "://" in raw_path or raw_path.startswith("//"):
        return raw_path
    clean_host = str(host_hint or "").strip()
    if not clean_host:
        return raw_path

    base_parsed = urlsplit(guard.base_origin)
    base_scheme = base_parsed.scheme.lower()
    base_host = (base_parsed.hostname or "").lower().rstrip(".")

    if "://" in clean_host:
        return urljoin(clean_host.rstrip("/") + "/", raw_path if raw_path.startswith("/") else "/" + raw_path)

    try:
        parsed_host = urlsplit(f"{base_scheme}://{clean_host}")
        explicit_port = parsed_host.port
    except ValueError:
        return f"{base_scheme}://{clean_host}{raw_path if raw_path.startswith('/') else '/' + raw_path}"

    hint_hostname = (parsed_host.hostname or "").strip().lower().rstrip(".")
    if explicit_port is None and hint_hostname == base_host:
        return urljoin(guard.base_origin, raw_path)
    return f"{base_scheme}://{clean_host}{raw_path if raw_path.startswith('/') else '/' + raw_path}"


def _best_status_from_map(statuses: Any) -> int | None:
    if not isinstance(statuses, dict):
        return None
    best: int | None = None
    best_rank = -999
    for code_raw in statuses:
        code = _coerce_status(code_raw)
        if code is None:
            continue
        rank = _status_priority(code)
        if rank > best_rank:
            best_rank = rank
            best = code
    return best


def _parse_har(data: dict[str, Any]) -> list[_CandidateRoute]:
    log = data.get("log")
    if not isinstance(log, dict):
        return []
    entries = log.get("entries")
    if not isinstance(entries, list):
        return []

    out: list[_CandidateRoute] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request")
        if not isinstance(req, dict):
            continue
        url = str(req.get("url") or "").strip()
        if not url:
            continue
        method = _normalize_method(req.get("method"), default="GET")

        # Extract ONLY parameter/field names — never headers, cookies, or values.
        params: list[str] = []
        seen: set[str] = set()

        def _extend(names: Sequence[str]) -> None:
            for name in names:
                if name and name not in seen and len(params) < _MAX_PARAMS_PER_ROUTE:
                    seen.add(name)
                    params.append(name)

        if isinstance(req.get("queryString"), list):
            _extend(_extract_param_names(req["queryString"]))

        is_form = False
        post_data = req.get("postData")
        if isinstance(post_data, dict):
            mime = str(post_data.get("mimeType") or "").split(";", 1)[0].strip().lower()
            has_form_params = isinstance(post_data.get("params"), list) and bool(post_data["params"])
            if has_form_params:
                _extend(_extract_param_names(post_data["params"]))
            raw_text = post_data.get("text")
            if isinstance(raw_text, str) and raw_text.strip():
                _extend(_extract_body_field_names(raw_text, mime))
            if method in _WRITE_METHODS and (
                "x-www-form-urlencoded" in mime
                or "multipart/form-data" in mime
                or (has_form_params and "json" not in mime)
            ):
                is_form = True

        resp = entry.get("response")
        status = _coerce_status(resp.get("status")) if isinstance(resp, dict) else None
        safe_hdrs = _extract_safe_app_headers(req.get("headers"))
        out.append(
            _CandidateRoute(
                method=method,
                url=url,
                params=params,
                is_form=is_form,
                status=status,
                app_headers=safe_hdrs,
            )
        )
    return out


def _is_zap_dict(data: dict[str, Any]) -> bool:
    if "site" in data and isinstance(data["site"], (list, dict)):
        sites = data["site"] if isinstance(data["site"], list) else [data["site"]]
        if not sites or any(
            isinstance(s, dict) and any(k in s for k in ("@name", "@host", "alerts", "urls"))
            for s in sites
        ):
            return True
    if "urlsInScope" in data:
        return True
    if "alerts" in data and isinstance(data["alerts"], (list, dict)):
        return True
    if "urls" in data and (
        isinstance(data["urls"], dict)
        or any(k in data for k in ("@version", "@generated", "ascan", "ajax", "mode", "spider"))
    ):
        return True
    return False


def _parse_zap(data: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []

    raw_sites = data.get("site")
    sites = raw_sites if isinstance(raw_sites, list) else ([raw_sites] if isinstance(raw_sites, dict) else [])
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_origin = str(site.get("@name") or "").strip()
        if not site_origin and site.get("@host"):
            ssl_flag = str(site.get("@ssl") or "").strip().lower() in {"true", "1", "yes"}
            scheme = "https" if ssl_flag else "http"
            host = str(site.get("@host") or "").strip()
            port = str(site.get("@port") or "").strip()
            if port and not ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
                site_origin = f"{scheme}://{host}:{port}"
            elif host:
                site_origin = f"{scheme}://{host}"

        for raw_u in site.get("urls") or []:
            u = raw_u if isinstance(raw_u, str) else (raw_u.get("url") if isinstance(raw_u, dict) else "")
            u_str = str(u or "").strip()
            if u_str:
                out.append(_CandidateRoute(method="GET", url=_resolve_host_and_path(site_origin, u_str, guard)))

        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances")
            if isinstance(instances, list) and instances:
                for inst in instances:
                    if not isinstance(inst, dict):
                        continue
                    uri = str(inst.get("uri") or inst.get("url") or "").strip()
                    if not uri:
                        continue
                    method = _normalize_method(inst.get("method") or alert.get("method"), default="GET")
                    params = _extract_param_names([inst.get("param") or inst.get("parameter") or alert.get("param")])
                    out.append(
                        _CandidateRoute(
                            method=method,
                            url=_resolve_host_and_path(site_origin, uri, guard),
                            params=params,
                        )
                    )
            else:
                uri = str(alert.get("uri") or alert.get("url") or "").strip()
                if uri:
                    method = _normalize_method(alert.get("method"), default="GET")
                    params = _extract_param_names([alert.get("param") or alert.get("parameter")])
                    out.append(
                        _CandidateRoute(
                            method=method,
                            url=_resolve_host_and_path(site_origin, uri, guard),
                            params=params,
                        )
                    )

    raw_urls = data.get("urls") or data.get("urlsInScope") or []
    if isinstance(raw_urls, dict):
        raw_urls = raw_urls.get("urls") or []
    if isinstance(raw_urls, list):
        for item in raw_urls:
            if isinstance(item, str) and item.strip():
                out.append(_CandidateRoute(method="GET", url=item.strip()))
            elif isinstance(item, dict):
                u_str = str(item.get("url") or item.get("uri") or "").strip()
                if u_str:
                    method = _normalize_method(item.get("method"), default="GET")
                    params = _extract_param_names(item.get("params"))
                    out.append(_CandidateRoute(method=method, url=u_str, params=params))

    raw_alerts = data.get("alerts") or data.get("alert") or []
    if isinstance(raw_alerts, dict):
        raw_alerts = raw_alerts.get("alerts") or raw_alerts.get("alert") or []
    if isinstance(raw_alerts, list):
        for alert in raw_alerts:
            if not isinstance(alert, dict):
                continue
            uri = str(alert.get("url") or alert.get("uri") or "").strip()
            if not uri:
                continue
            method = _normalize_method(alert.get("method"), default="GET")
            params = _extract_param_names([alert.get("param") or alert.get("parameter")])
            out.append(_CandidateRoute(method=method, url=uri, params=params))

    return out


def _is_ffuf_dict(data: dict[str, Any]) -> bool:
    results = data.get("results") if "results" in data else data.get("Results")
    if not isinstance(results, list):
        return False
    if "commandline" in data or "config" in data:
        return True
    if not results:
        return "results" in data
    return any(isinstance(item, dict) and ("url" in item or "URL" in item) for item in results[:10])


def _parse_ffuf(data: dict[str, Any]) -> list[_CandidateRoute]:
    results = data.get("results") if isinstance(data.get("results"), list) else data.get("Results")
    if not isinstance(results, list):
        return []
    raw_cfg = data.get("config")
    cfg: dict[str, Any] = raw_cfg if isinstance(raw_cfg, dict) else {}
    default_method = _normalize_method(cfg.get("method"), default="GET")

    out: list[_CandidateRoute] = []
    for item in results:
        if isinstance(item, str) and item.strip():
            out.append(_CandidateRoute(method=default_method, url=item.strip()))
        elif isinstance(item, dict):
            url = str(item.get("url") or item.get("URL") or "").strip()
            if not url:
                continue
            method = _normalize_method(item.get("method"), default=default_method)
            status = _coerce_status(item.get("status") if "status" in item else item.get("status_code"))
            out.append(_CandidateRoute(method=method, url=url, status=status))
    return out


def _is_mitm_scope_dict(data: dict[str, Any]) -> bool:
    if not data:
        return False
    if any(k in _GENERIC_SEED_TOP_KEYS for k in data):
        return False
    for key, val in data.items():
        if _parse_method_path_key(key) is not None:
            return True
        if isinstance(val, dict) and val:
            if any(_parse_method_path_key(inner_k) is not None for inner_k in val):
                return True
    return False


def _extract_mitm_route_entry(
    route_key: str,
    info: Any,
    host_hint: str,
    guard: ScopeGuard,
) -> _CandidateRoute | None:
    parsed_key = _parse_method_path_key(route_key)
    if parsed_key is None:
        return None
    method, path = parsed_key
    params: list[str] = []
    status: int | None = None
    entry_host = host_hint
    candidate_url = ""

    if isinstance(info, dict):
        if info.get("host"):
            entry_host = str(info.get("host")).strip()
        raw_sample = str(info.get("sample_url") or info.get("url") or "").strip()
        if raw_sample:
            candidate_url = _resolve_host_and_path(entry_host, raw_sample, guard)
        else:
            candidate_url = _resolve_host_and_path(entry_host, path, guard)
        for pkey in ("params", "query_params", "body_fields", "fields"):
            params.extend(_extract_param_names(info.get(pkey)))
        if info.get("sample_query"):
            params.extend(_extract_param_names(str(info.get("sample_query"))))
        status = _best_status_from_map(info.get("statuses")) or _coerce_status(info.get("status"))
    else:
        candidate_url = _resolve_host_and_path(entry_host, path, guard)

    if not candidate_url:
        return None
    return _CandidateRoute(method=method, url=candidate_url, params=params, status=status)


def _parse_mitm_scope_dict(data: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    for key, val in data.items():
        if _parse_method_path_key(key) is not None:
            rec = _extract_mitm_route_entry(str(key), val, "", guard)
            if rec is not None:
                out.append(rec)
        elif isinstance(val, dict):
            host_hint = str(key).strip()
            for inner_k, inner_v in val.items():
                rec = _extract_mitm_route_entry(str(inner_k), inner_v, host_hint, guard)
                if rec is not None:
                    out.append(rec)
    return out


def _is_nuclei_item(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    return any(k in item for k in ("matched-at", "matched_at", "template-id", "template_id", "matcher-name"))


def _parse_nuclei_items(items: Sequence[Any]) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = str(
            item.get("matched-at")
            or item.get("matched_at")
            or item.get("url")
            or item.get("host")
            or ""
        ).strip()
        if not url:
            continue
        method = _normalize_method(item.get("method"), default="")
        if not method:
            req_raw = item.get("request")
            if isinstance(req_raw, str):
                m_req = _REQUEST_LINE_METHOD_RE.match(req_raw.lstrip())
                if m_req:
                    method = m_req.group(1).upper()
        if not method:
            method = "GET"
        status = _coerce_status(item.get("status") or item.get("status-code"))
        out.append(_CandidateRoute(method=method, url=url, status=status))
    return out


def _parse_route_item(item: Any, *, default_method: str = "GET", is_form: bool = False) -> _CandidateRoute | None:
    if isinstance(item, str):
        line = item.strip()
        if not line:
            return None
        m_line = _METHOD_URL_LINE_RE.fullmatch(line)
        if m_line:
            return _CandidateRoute(method=m_line.group(1).upper(), url=m_line.group(2), is_form=is_form)
        if any(ch.isspace() for ch in line):
            return None
        return _CandidateRoute(method=default_method, url=line, is_form=is_form)

    if isinstance(item, dict):
        url = str(
            item.get("url")
            or item.get("path")
            or item.get("endpoint")
            or item.get("action")
            or item.get("href")
            or item.get("uri")
            or ""
        ).strip()
        if not url:
            return None
        method = _normalize_method(item.get("method"), default=default_method)
        params: list[str] = []
        for pkey in ("params", "query_params", "body_fields", "fields", "inputs", "body_keys"):
            params.extend(_extract_param_names(item.get(pkey)))
        body_template = _sanitize_seed_body_template(item.get("body_template"))
        if body_template is not None:
            params.extend(_extract_template_param_names(body_template))
        multipart_schema = _sanitize_multipart_schema(item.get("multipart_schema"))
        if multipart_schema is not None:
            params.extend(multipart_schema["fields"])
            params.extend(multipart_schema["files"])
        status = _coerce_status(item.get("status"))
        eff_is_form = bool(is_form or item.get("is_form"))
        return _CandidateRoute(
            method=method,
            url=url,
            params=params,
            is_form=eff_is_form,
            status=status,
            body_template=body_template,
            multipart_schema=multipart_schema,
        )
    return None


def _parse_generic_json(data: Any) -> list[_CandidateRoute]:
    out: list[_CandidateRoute] = []
    if isinstance(data, list):
        for item in data:
            rec = _parse_route_item(item)
            if rec is not None:
                out.append(rec)
        return out

    if not isinstance(data, dict):
        return out

    found_collection = any(
        k in data for k in ("schema", "body_templates", "multipart_schemas", "ws_endpoints", "discovery_hints")
    )
    for list_key in ("routes", "urls", "endpoints", "links", "pages", "js_calls", "spa_routes", "api_requests"):
        arr = data.get(list_key)
        if isinstance(arr, list):
            found_collection = True
            for item in arr:
                rec = _parse_route_item(item)
                if rec is not None:
                    out.append(rec)

    forms = data.get("forms")
    if isinstance(forms, list):
        found_collection = True
        for item in forms:
            rec = _parse_route_item(item, default_method="GET", is_form=True)
            if rec is not None:
                out.append(rec)

    # Index parsed candidates by (method, raw_url) and (method, path) so top-level
    # body_templates / multipart_schemas attach cleanly to matching routes or create new ones.
    by_exact: dict[tuple[str, str], _CandidateRoute] = {}
    by_path: dict[tuple[str, str], _CandidateRoute] = {}
    for cand in out:
        by_exact.setdefault((cand.method, cand.url), cand)
        cand_path = urlsplit(cand.url).path or "/"
        by_path.setdefault((cand.method, cand_path), cand)

    def _find_schema_target(method_val: str, raw_target_url: str) -> _CandidateRoute | None:
        exact_hit = by_exact.get((method_val, raw_target_url))
        if exact_hit is not None:
            return exact_hit
        parsed_t = urlsplit(raw_target_url)
        if parsed_t.netloc:
            return None
        return by_path.get((method_val, parsed_t.path or "/"))

    raw_body_templates = data.get("body_templates")
    if isinstance(raw_body_templates, dict):
        for raw_key, raw_doc in raw_body_templates.items():
            parsed_key = _parse_method_url_key(raw_key)
            if parsed_key is None:
                continue
            bt = _sanitize_seed_body_template(raw_doc)
            if bt is None:
                continue
            bt_method, bt_url = parsed_key
            bt_params = _extract_template_param_names(bt)
            bt_path = urlsplit(bt_url).path or "/"
            target = _find_schema_target(bt_method, bt_url)
            if target is not None:
                target.body_template = _merge_body_templates(target.body_template, bt)
                target.params.extend(bt_params)
            else:
                created = _CandidateRoute(
                    method=bt_method,
                    url=bt_url,
                    params=bt_params,
                    body_template=bt,
                )
                out.append(created)
                by_exact[(bt_method, bt_url)] = created
                by_path[(bt_method, bt_path)] = created

    raw_multipart_schemas = data.get("multipart_schemas")
    if isinstance(raw_multipart_schemas, dict):
        for raw_key, raw_schema in raw_multipart_schemas.items():
            parsed_key = _parse_method_url_key(raw_key)
            if parsed_key is None:
                continue
            ms = _sanitize_multipart_schema(raw_schema)
            if ms is None:
                continue
            mp_method, mp_url = parsed_key
            mp_params = [*ms["fields"], *ms["files"]]
            mp_path = urlsplit(mp_url).path or "/"
            target = _find_schema_target(mp_method, mp_url)
            if target is not None:
                target.multipart_schema = _merge_multipart_schemas(target.multipart_schema, ms)
                target.params.extend(mp_params)
            else:
                created = _CandidateRoute(
                    method=mp_method,
                    url=mp_url,
                    params=mp_params,
                    is_form=True,
                    multipart_schema=ms,
                )
                out.append(created)
                by_exact[(mp_method, mp_url)] = created
                by_path[(mp_method, mp_path)] = created

    if not found_collection:
        single = _parse_route_item(data)
        if single is not None:
            out.append(single)
    return out


def _parse_plain_text(text: str, guard: ScopeGuard) -> list[_CandidateRoute]:
    base_scheme = urlsplit(guard.base_origin).scheme.lower()
    out: list[_CandidateRoute] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "{[\"'":
            continue
        method = "GET"
        target_str = line
        m_line = _METHOD_URL_LINE_RE.fullmatch(line)
        if m_line:
            method = m_line.group(1).upper()
            target_str = m_line.group(2)
        elif any(ch.isspace() for ch in line):
            continue

        # Treat schemeless `host.tld/path` lines as explicit host URLs so ScopeGuard
        # rejects off-origin hosts instead of interpreting them as relative paths.
        if (
            "://" not in target_str
            and not target_str.startswith(("/", "//"))
            and "/" in target_str
        ):
            first_seg = target_str.split("/", 1)[0]
            if not first_seg.startswith(".") and _SCHEMELESS_HOST_RE.fullmatch(first_seg):
                target_str = f"{base_scheme}://{target_str}"

        out.append(_CandidateRoute(method=method, url=target_str))
    return out


def _parse_multipart_schema_from_text(body_text: str) -> dict[str, list[str]] | None:
    """Extract sorted multipart form field and file parameter names from raw text."""
    if not body_text or "Content-Disposition:" not in body_text:
        return None
    fields: list[str] = []
    files: list[str] = []
    seen_fields: set[str] = set()
    seen_files: set[str] = set()
    for match in _MULTIPART_LINE_RE.finditer(body_text[:65536]):
        cd_line = match.group(1) or ""
        m_name = _MULTIPART_NAME_RE.search(f"Content-Disposition: {cd_line}")
        if not m_name:
            continue
        clean = _sanitize_param_name(m_name.group(1))
        if not clean:
            continue
        if _MULTIPART_FILENAME_RE.search(cd_line):
            if clean not in seen_files and len(files) < _MAX_PARAMS_PER_ROUTE:
                seen_files.add(clean)
                files.append(clean)
        else:
            if clean not in seen_fields and len(fields) < _MAX_PARAMS_PER_ROUTE:
                seen_fields.add(clean)
                fields.append(clean)
    if not fields and not files:
        return None
    return {"fields": sorted(fields), "files": sorted(files)}


def _parse_body_artifacts(
    body_text: str,
    mime_type: str = "",
) -> tuple[list[str], dict[str, Any] | None, dict[str, list[str]] | None, bool]:
    """Extract ``(params, redacted_body_template, multipart_schema, is_form)`` from a raw request body."""
    if not isinstance(body_text, str):
        return [], None, None, False
    raw = body_text.strip()
    if not raw:
        return [], None, None, False
    ctype = str(mime_type or "").split(";", 1)[0].strip().lower()

    if "multipart/form-data" in ctype or "Content-Disposition:" in raw:
        mp = _parse_multipart_schema_from_text(raw)
        if mp is not None:
            return [*mp["fields"], *mp["files"]], None, mp, True
        names = _extract_body_field_names(raw, ctype)
        return names, None, None, True

    if "json" in ctype or raw.startswith(("{", "[")):
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and parsed:
            bt = _sanitize_seed_body_template(parsed)
            params = _extract_template_param_names(parsed)
            return params, bt, None, False
        if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
            bt = _sanitize_seed_body_template(parsed[0])
            params = _extract_template_param_names(parsed[0])
            return params, bt, None, False
        if "json" in ctype:
            return [], None, None, False

    if "x-www-form-urlencoded" in ctype or ("=" in raw and not raw.startswith(("<", "{", "["))):
        pairs = parse_qsl(raw, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS)
        form_obj: dict[str, Any] = {}
        form_params: list[str] = []
        seen: set[str] = set()
        for k, v in pairs:
            clean_k = _sanitize_param_name(k)
            if not clean_k:
                continue
            if clean_k not in seen and len(form_params) < _MAX_PARAMS_PER_ROUTE:
                seen.add(clean_k)
                form_params.append(clean_k)
            if clean_k not in form_obj and len(form_obj) < _MAX_PARAMS_PER_ROUTE:
                form_obj[clean_k] = v
        bt = _sanitize_seed_body_template(form_obj) if form_obj else None
        return form_params, bt, None, True

    return [], None, None, False


def _is_burp_xml_text(stripped: str) -> bool:
    if not stripped.startswith("<"):
        return False
    head_low = stripped[:8192].lower()
    if "<items" in head_low or "<item>" in head_low or "<item " in head_low:
        return True
    if head_low.startswith("<?xml") and _XML_XXE_RE.search(stripped[:8192]):
        return True
    if _XML_XXE_RE.search(stripped[:8192]) and not _HTML_DOCTYPE_RE.match(stripped[:512]):
        return True
    return False


def _parse_raw_http_request_message(
    raw_req: str,
) -> tuple[str, str, list[tuple[str, str]], str]:
    """Parse a raw HTTP/1.x request message into ``(method, target, headers, body)``."""
    if "\r\n\r\n" in raw_req:
        head_block, body = raw_req.split("\r\n\r\n", 1)
    elif "\n\n" in raw_req:
        head_block, body = raw_req.split("\n\n", 1)
    else:
        head_block, body = raw_req, ""

    lines = [ln.rstrip("\r") for ln in head_block.splitlines() if ln.strip()]
    if not lines:
        return "", "", [], body
    req_parts = lines[0].strip().split()
    req_method = req_parts[0].upper() if req_parts else ""
    req_target = req_parts[1] if len(req_parts) >= 2 else ""

    headers: list[tuple[str, str]] = []
    for hline in lines[1:]:
        if ":" not in hline:
            continue
        hk, hv = hline.split(":", 1)
        headers.append((hk.strip(), hv.strip()))
    return req_method, req_target, headers, body


def _parse_burp_xml(text: str, guard: ScopeGuard) -> list[_CandidateRoute]:
    """Parse Burp Suite XML export with fail-closed XXE rejection and secret stripping."""
    # Always reject ANY <!ENTITY declaration anywhere in the raw XML first.
    if _XML_ENTITY_RE.search(text):
        raise ValueError("Burp XML seed rejected: DOCTYPE and ENTITY declarations are disallowed")
    # Check the XML prolog before the root <items>/<item> element untouched (blocks comment-smuggled DOCTYPE).
    root_match = _BURP_ROOT_TAG_RE.search(text)
    if root_match is None:
        if _XML_XXE_RE.search(text):
            raise ValueError("Burp XML seed rejected: DOCTYPE and ENTITY declarations are disallowed")
        scrubbed = text
    else:
        prolog = text[: root_match.start()]
        if _XML_XXE_RE.search(prolog):
            raise ValueError("Burp XML seed rejected: DOCTYPE and ENTITY declarations are disallowed")
        body = text[root_match.start() :]
        # Strip <response> blocks (CDATA and non-CDATA) so legitimate base64="false" HTML
        # responses containing <!DOCTYPE html> are not falsely rejected; _parse_burp_xml only reads requests.
        body_scrubbed = _BURP_RESPONSE_CDATA_RE.sub("", body)
        body_scrubbed = _BURP_RESPONSE_ELEM_RE.sub("", body_scrubbed)
        if _XML_XXE_RE.search(body_scrubbed):
            raise ValueError("Burp XML seed rejected: DOCTYPE and ENTITY declarations are disallowed")
        scrubbed = prolog + body_scrubbed
    try:
        root = ET.fromstring(scrubbed)
    except ET.ParseError:
        return []

    def _strip_ns(tag: str) -> str:
        return tag.rsplit("}", 1)[-1].lower()

    items: list[ET.Element] = []
    if _strip_ns(root.tag) == "item":
        items = [root]
    else:
        items = [el for el in root.iter() if _strip_ns(el.tag) == "item"]

    out: list[_CandidateRoute] = []
    for item in items:
        fields: dict[str, ET.Element] = {}
        for child in item:
            fields[_strip_ns(child.tag)] = child

        url_text = (fields["url"].text or "").strip() if "url" in fields and fields["url"].text else ""
        method_text = (fields["method"].text or "").strip() if "method" in fields and fields["method"].text else ""
        status_text = (fields["status"].text or "").strip() if "status" in fields and fields["status"].text else ""
        host_text = (fields["host"].text or "").strip() if "host" in fields and fields["host"].text else ""
        port_text = (fields["port"].text or "").strip() if "port" in fields and fields["port"].text else ""
        proto_text = (fields["protocol"].text or "").strip().lower() if "protocol" in fields and fields["protocol"].text else ""
        path_text = (fields["path"].text or "").strip() if "path" in fields and fields["path"].text else ""

        req_method = ""
        req_target = ""
        raw_headers: list[tuple[str, str]] = []
        req_body = ""
        if "request" in fields:
            req_el = fields["request"]
            raw_req_text = req_el.text or ""
            is_b64 = str(req_el.attrib.get("base64") or "").strip().lower() in {"true", "1", "yes"}
            decoded_req = raw_req_text
            if is_b64 and raw_req_text.strip():
                try:
                    decoded_req = base64.b64decode(raw_req_text.strip(), validate=False).decode(
                        "utf-8", errors="replace"
                    )
                except (ValueError, binascii.Error):
                    decoded_req = ""
            if decoded_req.strip():
                req_method, req_target, raw_headers, req_body = _parse_raw_http_request_message(decoded_req)

        if not url_text:
            target_path = path_text or req_target or "/"
            host_from_hdr = next((hv for hk, hv in raw_headers if hk.lower() == "host"), "")
            eff_host = host_text or host_from_hdr
            if target_path.lower().startswith(("http://", "https://")):
                url_text = target_path
            elif eff_host:
                scheme = proto_text if proto_text in {"http", "https"} else urlsplit(guard.base_origin).scheme.lower()
                if port_text and ":" not in eff_host:
                    is_default = (scheme == "https" and port_text == "443") or (scheme == "http" and port_text == "80")
                    authority = eff_host if is_default else f"{eff_host}:{port_text}"
                else:
                    authority = eff_host
                norm_tp = target_path if target_path.startswith("/") else "/" + target_path
                url_text = f"{scheme}://{authority}{norm_tp}"
            elif target_path:
                url_text = target_path

        if not url_text:
            continue

        method = _normalize_method(method_text or req_method, default="GET")
        status = _coerce_status(status_text)

        params: list[str] = []
        if req_target:
            req_q = urlsplit(req_target).query
            if req_q:
                params.extend(_extract_param_names(req_q))

        ctype = next((hv for hk, hv in raw_headers if hk.lower() == "content-type"), "")
        safe_hdrs = _extract_safe_app_headers(raw_headers)
        body_params, body_template, mp_schema, is_form = _parse_body_artifacts(req_body, ctype)
        params.extend(body_params)

        out.append(
            _CandidateRoute(
                method=method,
                url=url_text,
                params=params,
                is_form=is_form,
                status=status,
                body_template=body_template,
                multipart_schema=mp_schema,
                app_headers=safe_hdrs,
            )
        )
    return out


def _is_openapi_dict(data: Any) -> bool:
    return (
        isinstance(data, dict)
        and isinstance(data.get("paths"), dict)
        and ("openapi" in data or "swagger" in data)
    )


def _looks_like_openapi_yaml(stripped: str) -> bool:
    head = stripped[:8192]
    return bool(_OPENAPI_YAML_HEADER_RE.search(head) and _OPENAPI_YAML_PATHS_RE.search(head))


def _synthesize_openapi_schema_value(resolver: LocalSchema, raw_schema: Any, *, depth: int = 0) -> Any:
    """Synthesize a compact redacted placeholder JSON value from an OpenAPI/Swagger schema."""
    if depth > 4 or not isinstance(raw_schema, dict):
        return "sample"
    node = resolver.schema(raw_schema, depth)
    if not isinstance(node, dict):
        return "sample"
    if "example" in node:
        return node["example"]
    if "default" in node:
        return node["default"]
    if isinstance(node.get("enum"), list) and node["enum"]:
        return node["enum"][0]

    typ = resolver.type_of(node)
    if not typ and isinstance(node.get("properties"), dict):
        typ = "object"
    if typ == "object":
        props = node.get("properties")
        if not isinstance(props, dict) or not props:
            return {}
        out: dict[str, Any] = {}
        for prop_name, prop_schema in list(props.items())[:16]:
            if not isinstance(prop_name, str) or not prop_name.strip():
                continue
            resolved_prop = resolver.schema(prop_schema, depth + 1)
            if isinstance(resolved_prop, dict) and resolved_prop.get("readOnly") is True:
                continue
            out[prop_name] = _synthesize_openapi_schema_value(resolver, resolved_prop, depth=depth + 1)
        return out
    if typ == "array":
        items = node.get("items")
        if isinstance(items, dict):
            return [_synthesize_openapi_schema_value(resolver, items, depth=depth + 1)]
        return []
    if typ == "integer":
        minimum = node.get("minimum")
        if isinstance(minimum, (int, float)) and math.isfinite(minimum):
            return math.ceil(minimum)
        return 1
    if typ == "number":
        minimum = node.get("minimum")
        if isinstance(minimum, (int, float)) and math.isfinite(minimum):
            return float(minimum)
        return 1.0
    if typ == "boolean":
        return False
    if typ == "null":
        return None
    fmt = str(node.get("format") or "").lower()
    if fmt == "email":
        return "sample@example.test"
    if fmt in {"uri", "url"}:
        return "https://example.test/sample"
    if fmt == "date":
        return "2026-01-15"
    if fmt == "date-time":
        return "2026-01-15T10:00:00Z"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    return "sample"


def _resolve_openapi_server_bases(spec: dict[str, Any], guard: ScopeGuard) -> list[str]:
    """Resolve OpenAPI 3 ``servers`` or Swagger 2 ``host`` + ``basePath`` bases."""
    bases: list[str] = []
    base_parsed = urlsplit(guard.base_origin)
    base_scheme = (base_parsed.scheme or "https").lower()

    servers = spec.get("servers")
    if isinstance(servers, list):
        for srv in servers[:8]:
            if not isinstance(srv, dict):
                continue
            srv_url = str(srv.get("url") or "").strip()
            if not srv_url:
                continue
            variables = srv.get("variables")
            if isinstance(variables, dict) and "{" in srv_url:
                for vname, vmeta in variables.items():
                    if isinstance(vmeta, dict) and vmeta.get("default") is not None:
                        srv_url = srv_url.replace("{" + str(vname) + "}", str(vmeta["default"]))
            if "{" in srv_url:
                continue
            if srv_url.lower().startswith(("http://", "https://")):
                cand = srv_url.rstrip("/")
            elif srv_url.startswith("/"):
                cand = guard.base_origin.rstrip("/") + srv_url.rstrip("/")
            else:
                continue
            if cand and cand not in bases:
                bases.append(cand)
        if bases:
            return bases

    raw_host = str(spec.get("host") or "").strip()
    raw_bp = str(spec.get("basePath") or "").strip()
    bp_clean = ""
    if raw_bp and raw_bp != "/" and "{" not in raw_bp:
        bp_clean = "/" + raw_bp.strip("/")

    if raw_host and "{" not in raw_host:
        raw_schemes = spec.get("schemes")
        schemes = (
            [str(s).strip().lower() for s in raw_schemes if str(s).strip().lower() in {"http", "https"}]
            if isinstance(raw_schemes, list)
            else []
        )
        chosen_scheme = ""
        try:
            host_parsed = urlsplit(f"{base_scheme}://{raw_host}")
            h_name = (host_parsed.hostname or "").lower()
            h_port = host_parsed.port
        except ValueError:
            h_name = ""
            h_port = None
        for sch in ([base_scheme] if base_scheme in schemes else []) + schemes + [base_scheme]:
            if not sch:
                continue
            eff_port = h_port if h_port is not None else (443 if sch == "https" else 80)
            if h_name and guard.check_origin(sch, h_name, eff_port):
                chosen_scheme = sch
                break
        if not chosen_scheme:
            chosen_scheme = "https" if "https" in schemes else (schemes[0] if schemes else base_scheme)
        return [f"{chosen_scheme}://{raw_host}{bp_clean}".rstrip("/")]

    if bp_clean:
        return [f"{guard.base_origin.rstrip('/')}{bp_clean}"]
    return [guard.base_origin.rstrip("/")]


def _join_openapi_base_and_path(server_base: str, raw_path: str) -> str:
    norm_raw = raw_path if raw_path.startswith("/") else "/" + raw_path
    parsed = urlsplit(server_base)
    srv_origin = f"{parsed.scheme.lower()}://{parsed.netloc}" if parsed.netloc else server_base.rstrip("/")
    srv_prefix = (parsed.path or "").rstrip("/")
    if srv_prefix and (
        norm_raw.lower() == srv_prefix.lower()
        or norm_raw.lower().startswith(srv_prefix.lower() + "/")
    ):
        return srv_origin.rstrip("/") + norm_raw
    return server_base.rstrip("/") + norm_raw


def _parse_openapi_spec(spec: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    """Parse OpenAPI 3.x or Swagger 2.0 dict into scope-filterable candidates with templates."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    resolver = LocalSchema(spec)
    server_bases = _resolve_openapi_server_bases(spec, guard)
    out: list[_CandidateRoute] = []

    for raw_path, raw_path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(raw_path_item, dict):
            continue
        path_item = resolver.resolve(raw_path_item)
        if not isinstance(path_item, dict):
            continue
        raw_pp = path_item.get("parameters")
        path_params: list[Any] = raw_pp if isinstance(raw_pp, list) else []

        for method_low in ("get", "post", "put", "patch", "delete", "head", "options"):
            raw_op = path_item.get(method_low)
            if not isinstance(raw_op, dict):
                continue
            op = resolver.resolve(raw_op)
            method = method_low.upper()
            op_params: list[str] = []
            body_template: dict[str, Any] | None = None
            multipart_schema: dict[str, list[str]] | None = None
            is_form = False
            form_fields: list[str] = []
            form_files: list[str] = []
            form_template_obj: dict[str, Any] = {}

            raw_op_p = op.get("parameters")
            raw_op_params: list[Any] = raw_op_p if isinstance(raw_op_p, list) else []
            for p_raw in [*path_params, *raw_op_params]:
                p_obj = resolver.resolve(p_raw) if isinstance(p_raw, dict) else {}
                if not isinstance(p_obj, dict):
                    continue
                pname = _sanitize_param_name(p_obj.get("name"))
                pin = str(p_obj.get("in") or "query").strip().lower()
                if pin == "body" and isinstance(p_obj.get("schema"), dict):
                    synth = _synthesize_openapi_schema_value(resolver, p_obj["schema"])
                    if isinstance(synth, dict) and synth:
                        bt = _sanitize_seed_body_template(synth)
                        if bt is not None:
                            body_template = _merge_body_templates(body_template, bt)
                            op_params.extend(_extract_template_param_names(bt))
                elif pin == "formdata" and pname:
                    is_form = True
                    op_params.append(pname)
                    ptype = str(p_obj.get("type") or "").strip().lower()
                    if ptype == "file":
                        form_files.append(pname)
                    else:
                        form_fields.append(pname)
                        form_template_obj[pname] = p_obj.get("default", "sample")
                elif pname and pin in {"query", "path"}:
                    op_params.append(pname)

            if form_files:
                multipart_schema = _sanitize_multipart_schema({"fields": form_fields, "files": form_files})
            elif form_template_obj and body_template is None:
                body_template = _sanitize_seed_body_template(form_template_obj)

            if isinstance(op.get("requestBody"), dict):
                req_body = resolver.resolve(op["requestBody"])
                content = req_body.get("content") if isinstance(req_body, dict) else None
                if isinstance(content, dict):
                    for ct_key, ct_val in content.items():
                        if not isinstance(ct_val, dict):
                            continue
                        ct_low = str(ct_key or "").split(";", 1)[0].strip().lower()
                        if ct_low == "application/json" or ct_low.endswith("+json"):
                            synth_obj: Any = None
                            if isinstance(ct_val.get("example"), dict):
                                synth_obj = ct_val["example"]
                            elif isinstance(ct_val.get("schema"), dict):
                                synth_obj = _synthesize_openapi_schema_value(resolver, ct_val["schema"])
                            if isinstance(synth_obj, dict) and synth_obj:
                                bt = _sanitize_seed_body_template(synth_obj)
                                if bt is not None:
                                    body_template = _merge_body_templates(body_template, bt)
                                    op_params.extend(_extract_template_param_names(bt))
                        elif ct_low == "application/x-www-form-urlencoded":
                            is_form = True
                            if isinstance(ct_val.get("schema"), dict):
                                synth_form = _synthesize_openapi_schema_value(resolver, ct_val["schema"])
                                if isinstance(synth_form, dict) and synth_form:
                                    bt = _sanitize_seed_body_template(synth_form)
                                    if bt is not None:
                                        body_template = _merge_body_templates(body_template, bt)
                                        op_params.extend(_extract_template_param_names(bt))
                        elif ct_low == "multipart/form-data":
                            is_form = True
                            if isinstance(ct_val.get("schema"), dict):
                                mp_schema = resolver.schema(ct_val["schema"])
                                props = mp_schema.get("properties") if isinstance(mp_schema, dict) else None
                                if isinstance(props, dict) and props:
                                    mp_fields: list[str] = []
                                    mp_files: list[str] = []
                                    for pk, pv in list(props.items())[:_MAX_PARAMS_PER_ROUTE]:
                                        clean_pk = _sanitize_param_name(pk)
                                        if not clean_pk:
                                            continue
                                        r_pv = resolver.schema(pv) if isinstance(pv, dict) else pv
                                        fmt = str(r_pv.get("format") or "").lower() if isinstance(r_pv, dict) else ""
                                        if fmt in {"binary", "byte"}:
                                            mp_files.append(clean_pk)
                                        else:
                                            mp_fields.append(clean_pk)
                                    san_mp = _sanitize_multipart_schema({"fields": mp_fields, "files": mp_files})
                                    if san_mp is not None:
                                        multipart_schema = _merge_multipart_schemas(multipart_schema, san_mp)
                                        op_params.extend(san_mp["fields"])
                                        op_params.extend(san_mp["files"])

            for srv_base in server_bases:
                full_url = _join_openapi_base_and_path(srv_base, raw_path)
                out.append(
                    _CandidateRoute(
                        method=method,
                        url=full_url,
                        params=list(op_params),
                        is_form=is_form,
                        body_template=body_template,
                        multipart_schema=multipart_schema,
                    )
                )
    return out


def _is_postman_dict(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    info = data.get("info")
    if not isinstance(info, dict) or not isinstance(data.get("item"), list):
        return False
    schema_str = str(info.get("schema") or "").lower()
    return (
        "_postman_id" in info
        or "getpostman.com" in schema_str
        or "schema.postman.com" in schema_str
    )


def _extract_postman_variables(raw_vars: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(raw_vars, list):
        return out
    for entry in raw_vars:
        if not isinstance(entry, dict) or entry.get("disabled"):
            continue
        key = str(entry.get("key") or "").strip()
        val = entry.get("value")
        if not key or val is None:
            continue
        val_s = str(val).strip()
        if not val_s or _is_sensitive_template_key(key):
            continue
        out[key] = val_s
    return out


def _resolve_postman_url_vars(raw_url: str, variables: dict[str, str], guard: ScopeGuard) -> str:
    url = str(raw_url or "").strip()
    if not url:
        return ""
    vars_low = {k.lower(): v for k, v in variables.items()}

    def _lookup(vname: str) -> str:
        if vname in variables:
            return variables[vname]
        return vars_low.get(vname.lower(), "")

    lead = _LEADING_POSTMAN_VAR_RE.match(url)
    if lead:
        vname = lead.group(1)
        resolved_prefix = _lookup(vname)
        if not resolved_prefix:
            resolved_prefix = guard.base_origin.rstrip("/")
        else:
            resolved_prefix = resolved_prefix.rstrip("/")
            if "://" not in resolved_prefix and not resolved_prefix.startswith("/"):
                base_scheme = urlsplit(guard.base_origin).scheme.lower()
                resolved_prefix = f"{base_scheme}://{resolved_prefix}"
        url = resolved_prefix + url[lead.end() :]

    def _replace_rest(match: re.Match[str]) -> str:
        vname = match.group(1)
        found = _lookup(vname)
        if found:
            return found
        return "{" + vname + "}"

    if "{{" in url:
        if "?" in url:
            head_part, query_part = url.split("?", 1)
            head_part = _POSTMAN_VAR_RE.sub(_replace_rest, head_part)
            url = f"{head_part}?{query_part}"
        else:
            url = _POSTMAN_VAR_RE.sub(_replace_rest, url)
    return url


def _extract_postman_raw_url_and_query(req_url: Any) -> tuple[str, list[str]]:
    if isinstance(req_url, str):
        return req_url.strip(), []
    if not isinstance(req_url, dict):
        return "", []
    extra_q: list[str] = []
    raw_query = req_url.get("query")
    if isinstance(raw_query, list):
        for q in raw_query:
            if isinstance(q, dict) and q.get("key") and not q.get("disabled"):
                clean = _sanitize_param_name(q.get("key"))
                if clean:
                    extra_q.append(clean)
    raw = str(req_url.get("raw") or "").strip()
    if raw:
        return raw, extra_q
    protocol = str(req_url.get("protocol") or "https").strip()
    host_val = req_url.get("host")
    if isinstance(host_val, list):
        host = ".".join(str(part).strip() for part in host_val if str(part).strip())
    else:
        host = str(host_val or "").strip()
    port = str(req_url.get("port") or "").strip()
    path_val = req_url.get("path")
    if isinstance(path_val, list):
        path = "/" + "/".join(str(seg).strip("/") for seg in path_val if str(seg).strip("/"))
    else:
        path_s = str(path_val or "").strip()
        path = path_s if (not path_s or path_s.startswith("/")) else "/" + path_s
    if host:
        if _LEADING_POSTMAN_VAR_RE.fullmatch(host):
            return f"{host}{path}", extra_q
        authority = f"{host}:{port}" if port else host
        return f"{protocol}://{authority}{path}", extra_q
    return path, extra_q


def _parse_postman_collection(data: dict[str, Any], guard: ScopeGuard) -> list[_CandidateRoute]:
    """Recursively parse Postman Collection v2.0 / v2.1 JSON into scope-filterable candidates."""
    root_vars = _extract_postman_variables(data.get("variable"))
    out: list[_CandidateRoute] = []

    def _walk(items: list[Any], scoped_vars: dict[str, str], depth: int = 0) -> None:
        if depth > 24:
            return
        for entry in items:
            if not isinstance(entry, dict):
                continue
            cur_vars = scoped_vars
            if isinstance(entry.get("variable"), list):
                cur_vars = {**scoped_vars, **_extract_postman_variables(entry.get("variable"))}

            req = entry.get("request")
            if isinstance(req, str) and req.strip():
                resolved_u = _resolve_postman_url_vars(req.strip(), cur_vars, guard)
                if resolved_u:
                    out.append(_CandidateRoute(method="GET", url=resolved_u))
            elif isinstance(req, dict):
                method = _normalize_method(req.get("method"), default="GET")
                raw_u, q_params = _extract_postman_raw_url_and_query(req.get("url"))
                resolved_u = _resolve_postman_url_vars(raw_u, cur_vars, guard)
                if resolved_u:
                    raw_hdrs = req.get("header")
                    safe_hdrs = _extract_safe_app_headers(raw_hdrs)
                    ctype = ""
                    if isinstance(raw_hdrs, list):
                        for h in raw_hdrs:
                            if isinstance(h, dict) and not h.get("disabled"):
                                hk = str(h.get("key") or h.get("name") or "").strip().lower()
                                if hk == "content-type":
                                    ctype = str(h.get("value") or "").strip()
                                    break

                    params: list[str] = list(q_params)
                    body_template: dict[str, Any] | None = None
                    mp_schema: dict[str, list[str]] | None = None
                    is_form = False

                    body = req.get("body")
                    if isinstance(body, dict):
                        mode = str(body.get("mode") or "").strip().lower()
                        raw_text = body.get("raw")
                        if mode == "raw" or (not mode and isinstance(raw_text, str)):
                            opts = body.get("options")
                            raw_lang = ""
                            if isinstance(opts, dict) and isinstance(opts.get("raw"), dict):
                                raw_lang = str(opts["raw"].get("language") or "").strip().lower()
                            eff_ctype = ctype or ("application/json" if raw_lang == "json" else "")
                            if isinstance(raw_text, str) and raw_text.strip():
                                bp, bt, mp, frm = _parse_body_artifacts(raw_text, eff_ctype)
                                params.extend(bp)
                                body_template = _merge_body_templates(body_template, bt)
                                mp_schema = _merge_multipart_schemas(mp_schema, mp)
                                is_form = is_form or frm
                        elif mode == "urlencoded":
                            is_form = True
                            form_obj: dict[str, Any] = {}
                            for item_u in body.get("urlencoded") or ():
                                if not isinstance(item_u, dict) or item_u.get("disabled"):
                                    continue
                                clean_k = _sanitize_param_name(item_u.get("key"))
                                if clean_k:
                                    params.append(clean_k)
                                    if clean_k not in form_obj and len(form_obj) < _MAX_PARAMS_PER_ROUTE:
                                        form_obj[clean_k] = str(item_u.get("value") or "")
                            if form_obj:
                                body_template = _sanitize_seed_body_template(form_obj)
                        elif mode == "formdata":
                            is_form = True
                            mp_fields: list[str] = []
                            mp_files: list[str] = []
                            for item_f in body.get("formdata") or ():
                                if not isinstance(item_f, dict) or item_f.get("disabled"):
                                    continue
                                clean_k = _sanitize_param_name(item_f.get("key"))
                                if not clean_k:
                                    continue
                                params.append(clean_k)
                                if str(item_f.get("type") or "").strip().lower() == "file":
                                    mp_files.append(clean_k)
                                else:
                                    mp_fields.append(clean_k)
                            mp_schema = _sanitize_multipart_schema({"fields": mp_fields, "files": mp_files})
                        elif mode == "graphql" and isinstance(body.get("graphql"), dict):
                            gql = body["graphql"]
                            gql_tmpl: dict[str, Any] = {}
                            if isinstance(gql.get("query"), str) and gql["query"].strip():
                                params.append("query")
                                gql_tmpl["query"] = gql["query"].strip()[:120]
                            gql_vars = gql.get("variables")
                            parsed_vars: Any = None
                            if isinstance(gql_vars, str) and gql_vars.strip().startswith("{"):
                                try:
                                    parsed_vars = json.loads(gql_vars)
                                except ValueError:
                                    parsed_vars = None
                            elif isinstance(gql_vars, dict):
                                parsed_vars = gql_vars
                            if isinstance(parsed_vars, dict) and parsed_vars:
                                params.append("variables")
                                params.extend(_extract_template_param_names(parsed_vars))
                                gql_tmpl["variables"] = parsed_vars
                            if gql_tmpl:
                                body_template = _sanitize_seed_body_template(gql_tmpl)

                    out.append(
                        _CandidateRoute(
                            method=method,
                            url=resolved_u,
                            params=params,
                            is_form=is_form,
                            body_template=body_template,
                            multipart_schema=mp_schema,
                            app_headers=safe_hdrs,
                        )
                    )

            children = entry.get("item")
            if isinstance(children, list):
                _walk(children, cur_vars, depth + 1)

    _walk(data["item"], root_vars)
    return out


def _join_shell_continuations(text: str) -> str:
    return re.sub(r"\\\r?\n[ \t]*", " ", text)


def _looks_like_curl_text(text: str) -> bool:
    joined = _join_shell_continuations(text)
    for raw_line in joined.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _CURL_LINE_RE.match(line):
            return True
    return False


def _parse_single_curl_command(line: str, guard: ScopeGuard) -> _CandidateRoute | None:
    try:
        tokens = shlex.split(line)
    except ValueError:
        return None
    if not tokens or tokens[0].lower() != "curl":
        return None

    explicit_method = ""
    force_get = False
    head_only = False
    target_url = ""
    raw_headers: list[tuple[str, str]] = []
    data_payloads: list[str] = []
    form_fields: list[str] = []
    form_files: list[str] = []

    i = 1
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        i += 1
        if tok == "--":
            if i < n and not target_url:
                target_url = tokens[i]
            break

        flag = tok
        attached_val: str | None = None
        if tok.startswith("--") and "=" in tok:
            flag, attached_val = tok.split("=", 1)
        elif len(tok) > 2 and tok.startswith("-") and not tok.startswith("--"):
            short = tok[:2]
            if short in {"-X", "-H", "-d", "-F", "-b", "-c", "-u", "-U", "-A", "-e", "-o", "-x", "-m", "-w"}:
                flag = short
                attached_val = tok[2:]

        def _consume_arg() -> str:
            nonlocal i
            if attached_val is not None:
                return attached_val
            if i < n:
                val = tokens[i]
                i += 1
                return val
            return ""

        if flag in {"-X", "--request"}:
            explicit_method = _consume_arg().strip().upper()
        elif flag == "--url":
            cand = _consume_arg().strip()
            if cand and not target_url:
                target_url = cand
        elif flag in {"-H", "--header"}:
            hdr_str = _consume_arg()
            if ":" in hdr_str:
                hk, hv = hdr_str.split(":", 1)
                raw_headers.append((hk.strip(), hv.strip()))
        elif flag in _CURL_DATA_FLAGS:
            payload = _consume_arg()
            if payload:
                data_payloads.append(payload)
        elif flag in _CURL_FORM_FLAGS:
            form_entry = _consume_arg()
            if "=" in form_entry:
                fname, fval = form_entry.split("=", 1)
                clean_fn = _sanitize_param_name(fname)
                if clean_fn:
                    if fval.lstrip().startswith(("@", "<")) and flag != "--form-string":
                        form_files.append(clean_fn)
                    else:
                        form_fields.append(clean_fn)
        elif flag in {"-G", "--get"}:
            force_get = True
        elif flag in {"-I", "--head"}:
            head_only = True
        elif flag in _CURL_DISCARD_ARG_FLAGS:
            _consume_arg()
        elif flag.startswith("-"):
            continue
        else:
            if not target_url:
                target_url = tok

    if not target_url:
        return None
    if (
        "://" not in target_url
        and not target_url.startswith(("/", "//"))
        and "/" in target_url
    ):
        first_seg = target_url.split("/", 1)[0]
        if not first_seg.startswith(".") and _SCHEMELESS_HOST_RE.fullmatch(first_seg):
            base_scheme = urlsplit(guard.base_origin).scheme.lower()
            target_url = f"{base_scheme}://{target_url}"

    if explicit_method:
        method = _normalize_method(explicit_method, default="GET")
    elif force_get:
        method = "GET"
    elif head_only:
        method = "HEAD"
    elif data_payloads or form_fields or form_files:
        method = "POST"
    else:
        method = "GET"

    ctype = next((hv for hk, hv in raw_headers if hk.lower() == "content-type"), "")
    safe_hdrs = _extract_safe_app_headers(raw_headers)
    params: list[str] = []
    body_template: dict[str, Any] | None = None
    mp_schema: dict[str, list[str]] | None = None
    is_form = False

    if form_fields or form_files:
        is_form = True
        mp_schema = _sanitize_multipart_schema({"fields": form_fields, "files": form_files})
        if mp_schema is not None:
            params.extend(mp_schema["fields"])
            params.extend(mp_schema["files"])

    if data_payloads:
        if force_get:
            for dp in data_payloads:
                params.extend(_extract_param_names(dp))
        else:
            combined = "&".join(data_payloads) if len(data_payloads) > 1 and not data_payloads[0].lstrip().startswith(("{", "[")) else data_payloads[0]
            bp, bt, mp, frm = _parse_body_artifacts(combined, ctype)
            params.extend(bp)
            body_template = _merge_body_templates(body_template, bt)
            mp_schema = _merge_multipart_schemas(mp_schema, mp)
            is_form = is_form or frm

    return _CandidateRoute(
        method=method,
        url=target_url,
        params=params,
        is_form=is_form,
        body_template=body_template,
        multipart_schema=mp_schema,
        app_headers=safe_hdrs,
    )


def _parse_curl_text(text: str, guard: ScopeGuard) -> list[_CandidateRoute]:
    """Parse one or more ``curl ...`` commands into scope-filterable, secret-stripped routes."""
    joined = _join_shell_continuations(text)
    out: list[_CandidateRoute] = []
    for raw_line in joined.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not _CURL_LINE_RE.match(line):
            continue
        rec = _parse_single_curl_command(line, guard)
        if rec is not None:
            out.append(rec)
    return out


class _YAMLResourceLimitError(ValueError):
    """Raised when an OpenAPI YAML document exceeds bounded node/alias/depth limits."""


def _load_safe_openapi_yaml(
    text: str,
    *,
    max_nodes: int = _MAX_OPENAPI_YAML_NODES,
    max_depth: int = _MAX_OPENAPI_YAML_DEPTH,
) -> Any:
    """Safely load an OpenAPI YAML document with bounded alias expansion, node count, and depth."""
    import yaml  # type: ignore[import-untyped]

    safe_loader_base = yaml.SafeLoader
    alias_event_cls = yaml.AliasEvent

    class _BoundedSafeLoader(safe_loader_base):  # type: ignore[valid-type,misc]
        def __init__(self, stream: str) -> None:
            super().__init__(stream)
            self._max_nodes = max(1, int(max_nodes))
            self._max_depth = max(1, int(max_depth))
            self._total_nodes = 0
            self._constructed_nodes = 0
            self._depth = 0
            self._node_weights: dict[int, tuple[Any, int]] = {}

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self._depth >= self._max_depth:
                raise _YAMLResourceLimitError("YAML alias/node limit exceeded")
            if self.check_event(alias_event_cls):
                node = super().compose_node(parent, index)
                entry = self._node_weights.get(id(node))
                if entry is None:
                    # Referenced anchor is still being composed (cyclic alias).
                    raise _YAMLResourceLimitError("YAML alias/node limit exceeded")
                _ref_node, weight = entry
                self._total_nodes += weight
                if self._total_nodes > self._max_nodes:
                    raise _YAMLResourceLimitError("YAML alias/node limit exceeded")
                return node
            self._total_nodes += 1
            if self._total_nodes > self._max_nodes:
                raise _YAMLResourceLimitError("YAML alias/node limit exceeded")
            self._depth += 1
            before_total = self._total_nodes
            try:
                node = super().compose_node(parent, index)
            finally:
                self._depth -= 1
            subtree_weight = (self._total_nodes - before_total) + 1
            self._node_weights[id(node)] = (node, subtree_weight)
            return node

        def construct_object(self, node: Any, deep: bool = False) -> Any:
            self._constructed_nodes += 1
            if self._constructed_nodes > self._max_nodes:
                raise _YAMLResourceLimitError("YAML alias/node limit exceeded")
            return super().construct_object(node, deep=deep)

    loader = _BoundedSafeLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _parse_seed_text_with_extras(text: str, guard: ScopeGuard) -> tuple[str, list[_CandidateRoute], list[Any]]:
    """Auto-detect seed artifact format and parse candidate routes and optional ws_endpoints offline."""
    stripped = text.strip()
    if not stripped:
        return "text", [], []

    if _is_burp_xml_text(stripped):
        return "burp_xml", _parse_burp_xml(stripped, guard), []

    if stripped[0] in "{[":
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None

        if isinstance(parsed, dict):
            if isinstance(parsed.get("log"), dict) and isinstance(parsed["log"].get("entries"), list):
                return "har", _parse_har(parsed), []
            if _is_openapi_dict(parsed):
                return "openapi", _parse_openapi_spec(parsed, guard), []
            if _is_postman_dict(parsed):
                return "postman", _parse_postman_collection(parsed, guard), []
            if _is_zap_dict(parsed):
                return "zap", _parse_zap(parsed, guard), []
            if _is_ffuf_dict(parsed):
                return "ffuf", _parse_ffuf(parsed), []
            if _is_mitm_scope_dict(parsed):
                return "mitm_scope", _parse_mitm_scope_dict(parsed, guard), []
            if _is_nuclei_item(parsed):
                return "nuclei", _parse_nuclei_items([parsed]), []
            ws_raw = parsed.get("ws_endpoints")
            ws_list = list(ws_raw) if isinstance(ws_raw, list) else []
            fmt = "stage0_seed" if str(parsed.get("schema") or "").startswith("stage0-seed/") else "generic_json"
            return fmt, _parse_generic_json(parsed), ws_list

        if isinstance(parsed, list):
            if any(_is_nuclei_item(item) for item in parsed[:20]):
                return "nuclei", _parse_nuclei_items(parsed), []
            if any(
                isinstance(item, dict)
                and "method" in item
                and "url" in item
                and ("params" in item or "capture_redacted" in item or "statuses" in item)
                for item in parsed[:20]
            ):
                return "mitm_scope", _parse_generic_json(parsed), []
            return "generic_json", _parse_generic_json(parsed), []

        # JSONL fallback (e.g., nuclei JSONL or mitm_scope traffic JSONL)
        json_items: list[dict[str, Any]] = []
        for raw_line in stripped.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    json_items.append(obj)
        if json_items:
            if any(_is_nuclei_item(item) for item in json_items[:20]):
                return "nuclei", _parse_nuclei_items(json_items), []
            if any(
                "method" in item
                and "url" in item
                and ("params" in item or "capture_redacted" in item)
                for item in json_items[:20]
            ):
                return "mitm_scope", _parse_generic_json(json_items), []
            return "generic_json", _parse_generic_json(json_items), []
        return "text", [], []

    if _looks_like_openapi_yaml(stripped):
        try:
            import yaml as _yaml_probe  # noqa: F401  # type: ignore[import-untyped]
        except ImportError:
            return "openapi", [], []
        try:
            parsed_yaml = _load_safe_openapi_yaml(stripped)
        except _YAMLResourceLimitError:
            raise
        except Exception:
            parsed_yaml = None
        if _is_openapi_dict(parsed_yaml):
            return "openapi", _parse_openapi_spec(parsed_yaml, guard), []

    if _looks_like_curl_text(stripped):
        return "curl", _parse_curl_text(stripped, guard), []

    return "text", _parse_plain_text(stripped, guard), []


def _parse_seed_text(text: str, guard: ScopeGuard) -> tuple[str, list[_CandidateRoute]]:
    """Auto-detect seed artifact format and parse candidate routes offline."""
    fmt, candidates, _ = _parse_seed_text_with_extras(text, guard)
    return fmt, candidates


def _route_priority_score(route: _AcceptedRoute) -> int:
    """Compute a deterministic signal score favoring API, write, schema-rich, parameterized, and deeper routes."""
    score = 0
    path_only = urlsplit(route.path).path or "/"
    low = path_only.lower()

    if _API_PATH_RE.search(low):
        score += 40
    if route.method in _WRITE_METHODS:
        score += 30
    if route.multipart_schema:
        score += 18
    if route.body_template:
        score += 12
    if route.params:
        score += 20 + min(len(route.params), 5)
        if _has_high_risk_param(route.params):
            score += 10

    segments = [seg for seg in path_only.split("/") if seg]
    score += min(len(segments), 6) * 5
    if any(is_id_segment(seg) for seg in segments):
        score += 10
    if any(kw in low for kw in _HIGH_SIGNAL_KEYWORDS):
        score += 8
    if route.is_form:
        score += 5
    score += _status_priority(route.best_status)
    if low in _LOW_SIGNAL_EXACT_PATHS:
        score -= 15
    return score


def _is_non_hint_asset_path(path: str) -> bool:
    """Return True if `path` is a static/hashed frontend asset chunk or OS filesystem path.

    Such paths must never occupy `discovery_hints` slots, while real HTML/API/app
    endpoints (`/`, `/api/settings`, `/users`, `/internal/logs`, `/admin/index.html`,
    `/index/Article/info.html`, etc.) remain eligible.
    """
    raw = str(path or "").strip()
    if not raw:
        return False
    if is_hashed_asset_chunk_path(raw) or is_os_filesystem_path(raw):
        return True
    try:
        parsed_path = (urlsplit(raw).path or "").strip()
    except ValueError:
        return False
    if not parsed_path:
        return False
    if is_hashed_asset_chunk_path(parsed_path) or is_os_filesystem_path(parsed_path):
        return True
    trimmed = parsed_path.rstrip("/").lower()
    if not trimmed:
        return False
    return trimmed.endswith(_NON_HINT_STATIC_ASSET_EXTS)


def _select_discovery_hints(routes: Sequence[_AcceptedRoute], max_hints: int) -> list[str]:
    """Select up to `max_hints` diverse high-signal GET/entry `/path` or sibling-origin discovery hints."""
    cap = max(0, int(max_hints))
    if cap == 0:
        return []

    get_routes = [
        r
        for r in routes
        if r.method in {"GET", "HEAD"} and not _is_non_hint_asset_path(r.path)
    ]
    if not get_routes:
        return []

    def _hint_sort_key(route: _AcceptedRoute) -> tuple[int, int, int, str]:
        path_only = urlsplit(route.path).path or "/"
        segments = [seg for seg in path_only.split("/") if seg]
        has_id = 1 if any(is_id_segment(seg) for seg in segments) else 0
        is_get = 0 if route.method == "GET" else 1
        return (is_get, has_id, -_route_priority_score(route), route.path)

    ranked = sorted(get_routes, key=_hint_sort_key)
    selected: list[str] = []
    seen_paths: set[str] = set()
    seen_templates: set[str] = set()

    # Pass 1: maximize endpoint template diversity (per origin).
    for route in ranked:
        if len(selected) >= cap:
            return selected
        tmpl = _scoped_route_template(route.path)
        if route.path in seen_paths or tmpl in seen_templates:
            continue
        seen_paths.add(route.path)
        seen_templates.add(tmpl)
        selected.append(route.path)

    # Pass 2: fill any remaining slots with distinct concrete GET paths.
    for route in ranked:
        if len(selected) >= cap:
            break
        if route.path in seen_paths:
            continue
        seen_paths.add(route.path)
        selected.append(route.path)

    return selected


def _finalize_seed_surface(
    candidates: Sequence[_CandidateRoute],
    raw_ws_endpoints: Sequence[Any],
    *,
    guard: ScopeGuard,
    max_routes: int,
    max_discovery_hints: int,
    files_loaded: int = 0,
    initial_dropped_scope: int = 0,
    initial_dropped_static: int = 0,
    formats_detected: Sequence[str] = (),
    extra_discovery_hints: Sequence[str] = (),
    initial_app_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Scope-filter, sanitize, deduplicate, and rank candidate routes and WS endpoints."""
    effective_max_routes = max(0, int(max_routes))
    effective_max_hints = max(0, int(max_discovery_hints))

    routes_dropped_scope = max(0, int(initial_dropped_scope))
    routes_dropped_static = max(0, int(initial_dropped_static))
    accepted_by_key: dict[tuple[str, str], _AcceptedRoute] = {}
    merged_app_headers: dict[str, str] = {}
    if initial_app_headers:
        _merge_app_headers(merged_app_headers, initial_app_headers)
    seen_order = 0

    for cand in candidates:
        raw_url = str(cand.url or "").strip()
        if not raw_url:
            continue

        # Strict ScopeGuard enforcement BEFORE static filtering or normalization.
        try:
            guard.check_url(raw_url)
        except ValueError:
            routes_dropped_scope += 1
            continue

        resolved = urljoin(guard.base_origin, raw_url)
        parsed = urlsplit(resolved)
        try:
            norm_path = normalize_path(parsed.path or "/")
        except ValueError:
            routes_dropped_scope += 1
            continue

        if (
            is_static_asset_url(norm_path)
            or is_static_asset_url(resolved)
            or is_non_endpoint_source_path(norm_path)
            or is_non_endpoint_source_path(resolved)
        ):
            routes_dropped_static += 1
            continue

        if cand.app_headers:
            _merge_app_headers(merged_app_headers, cand.app_headers)

        method = _normalize_method(cand.method, default="GET")
        sanitized_bt = _sanitize_seed_body_template(cand.body_template)
        sanitized_mp = _sanitize_multipart_schema(cand.multipart_schema)

        # Extract ONLY parameter names from query string + parsed body/multipart fields; discard all values.
        param_names: list[str] = []
        param_seen: set[str] = set()

        def _add_param(raw_p: Any) -> None:
            clean_p = _sanitize_param_name(raw_p)
            if clean_p and clean_p not in param_seen and len(param_names) < _MAX_PARAMS_PER_ROUTE:
                param_seen.add(clean_p)
                param_names.append(clean_p)

        if parsed.query:
            for qk, _ in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=_MAX_QUERY_FIELDS):
                _add_param(qk)
        for extra_p in cand.params:
            _add_param(extra_p)
        if sanitized_bt is not None:
            for bt_p in _extract_template_param_names(sanitized_bt):
                _add_param(bt_p)
        if sanitized_mp is not None:
            for mp_p in (*sanitized_mp["fields"], *sanitized_mp["files"]):
                _add_param(mp_p)

        base_parsed = urlsplit(guard.base_origin)
        cand_port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        base_port = base_parsed.port or (443 if base_parsed.scheme.lower() == "https" else 80)
        same_origin_as_base = (
            parsed.scheme.lower() == base_parsed.scheme.lower()
            and (parsed.hostname or "").lower() == (base_parsed.hostname or "").lower()
            and cand_port == base_port
        )
        route_target = norm_path if same_origin_as_base else f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{norm_path}"

        key = (method, route_target)
        existing = accepted_by_key.get(key)
        if existing is None:
            seen_order += 1
            accepted_by_key[key] = _AcceptedRoute(
                method=method,
                path=route_target,
                params=sorted(param_names),
                is_form=bool(cand.is_form),
                best_status=cand.status,
                first_seen=seen_order,
                body_template=sanitized_bt,
                multipart_schema=sanitized_mp,
            )
        else:
            if param_names:
                merged = sorted(set(existing.params) | set(param_names))[:_MAX_PARAMS_PER_ROUTE]
                existing.params = merged
            if cand.is_form:
                existing.is_form = True
            if cand.status is not None and _status_priority(cand.status) > _status_priority(existing.best_status):
                existing.best_status = cand.status
            if sanitized_bt is not None:
                existing.body_template = _merge_body_templates(existing.body_template, sanitized_bt)
            if sanitized_mp is not None:
                existing.multipart_schema = _merge_multipart_schemas(existing.multipart_schema, sanitized_mp)

    ws_by_path: dict[str, dict[str, str]] = {}
    for raw_ws in raw_ws_endpoints:
        ws_entry, drop_reason = _normalize_ws_endpoint(raw_ws, guard)
        if ws_entry is None:
            if drop_reason == "scope":
                routes_dropped_scope += 1
            elif drop_reason == "static":
                routes_dropped_static += 1
            continue
        ws_by_path.setdefault(ws_entry["url"], ws_entry)
    ws_endpoints = [ws_by_path[p] for p in sorted(ws_by_path)]

    ranked_routes = sorted(
        accepted_by_key.values(),
        key=lambda r: (-_route_priority_score(r), r.first_seen, r.path, r.method),
    )
    kept_routes = ranked_routes[:effective_max_routes]

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    body_templates_map: dict[str, dict[str, Any]] = {}
    multipart_schemas_map: dict[str, dict[str, list[str]]] = {}

    for route in kept_routes:
        entry: dict[str, Any] = {
            "method": route.method,
            "url": route.path,
            "params": list(route.params),
        }
        if route.body_template is not None:
            entry["body_template"] = route.body_template
            tmpl_key = f"{route.method} {_scoped_route_template(route.path)}"
            merged_bt = _merge_body_templates(body_templates_map.get(tmpl_key), route.body_template)
            if merged_bt is not None:
                body_templates_map[tmpl_key] = merged_bt
        if route.multipart_schema is not None:
            entry["multipart_schema"] = route.multipart_schema
            tmpl_key = f"{route.method} {_scoped_route_template(route.path)}"
            merged_mp = _merge_multipart_schemas(multipart_schemas_map.get(tmpl_key), route.multipart_schema)
            if merged_mp is not None:
                multipart_schemas_map[tmpl_key] = merged_mp
        if route.is_form:
            forms.append(entry)
        else:
            links.append(entry)

    discovery_hints = _select_discovery_hints(kept_routes, effective_max_hints)
    if extra_discovery_hints and len(discovery_hints) < effective_max_hints:
        seen_hints = set(discovery_hints)
        base_parsed = urlsplit(guard.base_origin)
        base_port = base_parsed.port or (443 if base_parsed.scheme.lower() == "https" else 80)
        for raw_h in extra_discovery_hints:
            h_str = str(raw_h or "").strip()
            if not h_str:
                continue
            try:
                guard.check_url(h_str)
            except ValueError:
                continue
            resolved_h = urljoin(guard.base_origin, h_str)
            parsed_h = urlsplit(resolved_h)
            try:
                norm_path_h = normalize_path(parsed_h.path or "/")
            except ValueError:
                continue
            if (
                is_static_asset_url(norm_path_h)
                or is_non_endpoint_source_path(norm_path_h)
                or _is_non_hint_asset_path(norm_path_h)
            ):
                continue
            h_port = parsed_h.port or (443 if parsed_h.scheme.lower() == "https" else 80)
            same_origin_h = (
                parsed_h.scheme.lower() == base_parsed.scheme.lower()
                and (parsed_h.hostname or "").lower() == (base_parsed.hostname or "").lower()
                and h_port == base_port
            )
            norm_h = (
                norm_path_h
                if same_origin_h
                else f"{parsed_h.scheme.lower()}://{parsed_h.netloc.lower()}{norm_path_h}"
            )
            if norm_h not in seen_hints:
                seen_hints.add(norm_h)
                discovery_hints.append(norm_h)
                if len(discovery_hints) >= effective_max_hints:
                    break

    result: dict[str, Any] = {
        "url": guard.base_origin,
        "links": links,
        "forms": forms,
        "discovery_hints": discovery_hints,
        "body_templates": dict(sorted(body_templates_map.items())),
        "multipart_schemas": dict(sorted(multipart_schemas_map.items())),
        "app_headers": dict(sorted(merged_app_headers.items())),
        "stats": {
            "files_loaded": files_loaded,
            "routes_accepted": len(links) + len(forms),
            "routes_dropped_scope": routes_dropped_scope,
            "routes_dropped_static": routes_dropped_static,
            "formats_detected": list(formats_detected),
            "body_templates_count": len(body_templates_map),
            "multipart_schemas_count": len(multipart_schemas_map),
            "ws_endpoints_count": len(ws_endpoints),
        },
    }
    if ws_endpoints:
        result["ws_endpoints"] = ws_endpoints
    return result


def load_seed_surface_files(
    paths: Sequence[Path | str],
    *,
    base_url: str,
    excluded_paths: Sequence[str] = (),
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
    max_routes: int = 200,
    max_discovery_hints: int = 12,
) -> dict[str, Any]:
    """Load, scope-filter, secret-strip, deduplicate, and rank offline seed surface files."""
    guard = ScopeGuard(
        base_origin=base_url,
        excluded_paths=tuple(excluded_paths or ()),
        in_scope_assets=tuple(in_scope_assets or ()),
        out_of_scope_assets=tuple(out_of_scope_assets or ()),
    )

    files_loaded = 0
    formats_detected: list[str] = []
    all_candidates: list[_CandidateRoute] = []
    all_ws_endpoints: list[Any] = []
    top_app_headers: dict[str, str] = {}

    for raw_file in paths:
        text = _read_seed_file(raw_file)
        files_loaded += 1
        fmt, candidates, ws_items = _parse_seed_text_with_extras(text, guard)
        if fmt and fmt not in formats_detected:
            formats_detected.append(fmt)
        all_candidates.extend(candidates)
        all_ws_endpoints.extend(ws_items)
        if fmt in {"stage0_seed", "generic_json"} and text.lstrip().startswith("{"):
            try:
                raw_doc = json.loads(text)
            except ValueError:
                raw_doc = None
            if isinstance(raw_doc, dict):
                for hkey in ("app_headers", "observed_app_headers"):
                    if isinstance(raw_doc.get(hkey), dict):
                        _merge_app_headers(top_app_headers, raw_doc[hkey])

    return _finalize_seed_surface(
        all_candidates,
        all_ws_endpoints,
        guard=guard,
        max_routes=max_routes,
        max_discovery_hints=max_discovery_hints,
        files_loaded=files_loaded,
        formats_detected=formats_detected,
        initial_app_headers=top_app_headers,
    )


def merge_seed_surfaces(
    seed_dicts: Sequence[dict[str, Any] | None],
    *,
    base_url: str,
    excluded_paths: Sequence[str] = (),
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
    max_routes: int = 200,
    max_discovery_hints: int = 12,
) -> dict[str, Any] | None:
    """Combine multiple in-memory seed surface dicts with full ScopeGuard filtering and deduplication."""
    guard = ScopeGuard(
        base_origin=base_url,
        excluded_paths=tuple(excluded_paths or ()),
        in_scope_assets=tuple(in_scope_assets or ()),
        out_of_scope_assets=tuple(out_of_scope_assets or ()),
    )

    all_candidates: list[_CandidateRoute] = []
    all_ws_endpoints: list[Any] = []
    extra_hints: list[str] = []
    merged_app_headers: dict[str, str] = {}
    files_loaded = 0
    prior_dropped_scope = 0
    prior_dropped_static = 0
    formats_detected: list[str] = []

    for doc in seed_dicts:
        if not isinstance(doc, dict) or not doc:
            continue
        all_candidates.extend(_parse_generic_json(doc))
        for hkey in ("app_headers", "observed_app_headers"):
            if isinstance(doc.get(hkey), dict):
                _merge_app_headers(merged_app_headers, doc[hkey])
        ws_raw = doc.get("ws_endpoints")
        if isinstance(ws_raw, list):
            all_ws_endpoints.extend(ws_raw)
        hints_raw = doc.get("discovery_hints")
        if isinstance(hints_raw, list):
            for h in hints_raw:
                if isinstance(h, str) and h.strip():
                    extra_hints.append(h.strip())
        stats = doc.get("stats")
        if isinstance(stats, dict):
            if isinstance(stats.get("files_loaded"), int):
                files_loaded += max(0, stats["files_loaded"])
            if isinstance(stats.get("routes_dropped_scope"), int):
                prior_dropped_scope += max(0, stats["routes_dropped_scope"])
            if isinstance(stats.get("routes_dropped_static"), int):
                prior_dropped_static += max(0, stats["routes_dropped_static"])
            raw_fmts = stats.get("formats_detected")
            if isinstance(raw_fmts, list):
                for fmt in raw_fmts:
                    fmt_s = str(fmt or "").strip()
                    if fmt_s and fmt_s not in formats_detected:
                        formats_detected.append(fmt_s)
        schema_tag = str(doc.get("schema") or "").strip()
        if schema_tag.startswith("stage0-seed/") and "stage0_seed" not in formats_detected:
            formats_detected.append("stage0_seed")

    if not all_candidates and not all_ws_endpoints:
        return None

    merged = _finalize_seed_surface(
        all_candidates,
        all_ws_endpoints,
        guard=guard,
        max_routes=max_routes,
        max_discovery_hints=max_discovery_hints,
        files_loaded=files_loaded,
        initial_dropped_scope=prior_dropped_scope,
        initial_dropped_static=prior_dropped_static,
        formats_detected=formats_detected,
        extra_discovery_hints=extra_hints,
        initial_app_headers=merged_app_headers,
    )
    if (
        not merged["links"]
        and not merged["forms"]
        and not merged["body_templates"]
        and not merged["multipart_schemas"]
        and not merged.get("ws_endpoints")
    ):
        return None
    return merged


def apply_seed_surface(
    surface_tracker: SurfaceFrontierTracker,
    seed_data: dict[str, Any],
    *,
    actor: str = "seed",
) -> int:
    """Ingest loaded seed surface data into `SurfaceFrontierTracker` and return route count."""
    if not isinstance(seed_data, dict):
        return 0
    links = [item for item in (seed_data.get("links") or []) if isinstance(item, dict) and item.get("url")]
    forms = [item for item in (seed_data.get("forms") or []) if isinstance(item, dict) and item.get("url")]
    count = len(links) + len(forms)
    raw_bt = seed_data.get("body_templates")
    raw_mp = seed_data.get("multipart_schemas")
    raw_ws = seed_data.get("ws_endpoints")
    standalone = (
        (len(raw_bt) if isinstance(raw_bt, dict) else 0)
        + (len(raw_mp) if isinstance(raw_mp, dict) else 0)
        + (len(raw_ws) if isinstance(raw_ws, list) else 0)
    )
    if count == 0 and standalone == 0:
        return 0
    surface_tracker.ingest_surface(seed_data, actor=actor)
    return count if count > 0 else standalone


def _normalize_hint_path(raw: str) -> str:
    cleaned = str(raw or "").strip()
    if not cleaned:
        return ""
    parsed = urlsplit(cleaned)
    raw_path = parsed.path or "/"
    try:
        norm = normalize_path(raw_path)
    except ValueError:
        return ""
    if is_static_asset_url(norm) or _is_non_hint_asset_path(norm):
        return ""
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{norm}"
    return norm


def _canonicalize_tech_tags(tech_tags: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in tech_tags:
        for piece in re.split(r"[,;/\s]+", str(raw or "").strip()):
            token = re.sub(r"[^a-z0-9]+", "", piece.lower())
            if not token:
                continue
            canonical = _TECH_TAG_ALIASES.get(token, token)
            if canonical not in seen:
                seen.add(canonical)
                out.append(canonical)
    return out


def enrich_tech_discovery_hints(
    tech_tags: Sequence[str],
    *,
    existing_hints: Sequence[str] = (),
    max_added: int = 16,
) -> list[str]:
    """Optionally append deduplicated normalized `/path` hints for operator-specified tech tags."""
    result: list[str] = []
    seen: set[str] = set()

    for raw_hint in existing_hints:
        norm = _normalize_hint_path(raw_hint)
        if norm and norm.lower() not in seen:
            seen.add(norm.lower())
            result.append(norm)

    cap = max(0, int(max_added))
    canonical_tags = _canonicalize_tech_tags(tech_tags)
    if cap == 0 or not canonical_tags:
        return result

    candidates: list[str] = []

    # 1. Stack-specific built-in hints first (covers modern stacks like nextjs/fastapi/graphql/express).
    for tag in canonical_tags:
        for path in _BUILTIN_TECH_HINTS.get(tag, ()):
            candidates.append(path)

    # 2. Lazily query tech_routes.build_wordlist without making any network calls.
    try:
        import tech_routes  # type: ignore[import-not-found]
    except ImportError:
        tech_routes = None

    if tech_routes is not None:
        tag_blob = " ".join(str(t) for t in tech_tags if str(t or "").strip())
        base_set = {str(w).strip().lstrip("/").lower() for w in getattr(tech_routes, "BASE_ROUTES", ())}
        tech_map = getattr(tech_routes, "TECH_ROUTES", {})
        if isinstance(tech_map, dict):
            for tag in canonical_tags:
                for route in tech_map.get(tag, ()):
                    candidates.append(str(route))
        try:
            words, _ = tech_routes.build_wordlist(
                server=tag_blob,
                powered_by=tag_blob,
                body=tag_blob,
                budget=int(getattr(tech_routes, "MAX_ROUTES", 100)),
            )
        except Exception:
            words = []
        # Append tech-specific words from build_wordlist before generic BASE_ROUTES entries.
        tech_specific = [w for w in words if str(w).strip().lstrip("/").lower() not in base_set]
        generic_words = [w for w in words if str(w).strip().lstrip("/").lower() in base_set]
        candidates.extend(tech_specific)
        candidates.extend(generic_words)

    added = 0
    for raw_cand in candidates:
        if added >= cap:
            break
        norm = _normalize_hint_path(raw_cand)
        if not norm or norm.lower() in _LOW_VALUE_TECH_HINT_SEGMENTS:
            continue
        if norm.lower() in seen:
            continue
        seen.add(norm.lower())
        result.append(norm)
        added += 1

    return result
