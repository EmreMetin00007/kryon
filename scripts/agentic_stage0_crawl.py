"""Stage 0 deterministic, scope-locked headless Playwright surface crawler.

Provides a 4-layer, 100% target-agnostic pre-LLM web application discovery stage:
1. Network interception (`context.route` + request/response/websocket capture) with
   strict same-origin ScopeGuard, fail-closed method policy, bounded WireBudget
   slicing, JSON body template sanitization, and pure-Python multipart schema parsing.
2. Structural DOM state hashing (Light DOM + open Shadow DOM) and bounded BFS
   navigation with safe non-destructive UI control exploration.
3. Opt-in fail-closed form filling and synthetic file upload triggering (only active
   when ``allow_forms=True`` AND ``"POST" in http_client.allowed_methods``).
4. Passive surface fusion over captured HTML documents, same-origin JS chunks,
   bounded manifest probes, and OpenAPI schema synthesis.
"""
from __future__ import annotations

import base64
from collections import deque
from contextlib import nullcontext
from dataclasses import dataclass, field
import hashlib
import inspect
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import sys
import threading
import time
from typing import Any, Iterable, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_REPO_ROOT = _SCRIPTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_browser import (  # noqa: E402
    CHROMIUM_ARGS,
    HAS_PLAYWRIGHT as _BROWSER_HAS_PLAYWRIGHT,
    _BROWSER_USER_AGENT,
    _budget_remaining,
    _build_origin_localstorage_init_script,
    _collect_actor_secrets,
    _extract_actor_browser_auth,
    _extract_actor_local_storage,
    _merge_browser_route_headers,
    _operator_browser_headers,
    _operator_user_agent,
    _parse_cookie_pairs,
    _redact_secrets,
    _resolve_and_check_scope,
    _run_sync,
)
try:
    from agentic_browser import (  # noqa: E402
        _build_multi_origin_localstorage_init_script,
        _extract_actor_cookie_records,
        _extract_actor_local_storage_by_origin,
    )
except ImportError:  # pragma: no cover - backward-compatible fallback
    _build_multi_origin_localstorage_init_script = None  # type: ignore[assignment]
    _extract_actor_cookie_records = None  # type: ignore[assignment]
    _extract_actor_local_storage_by_origin = None  # type: ignore[assignment]
from agentic_http import (  # noqa: E402
    AgenticHTTPClient,
    BudgetExhaustedError,
    MethodNotAllowedError,
    ScopeViolationError,
    ServiceDegradationError,
    is_static_asset_url,
)
from agentic_preview import (  # noqa: E402
    _extract_surface_summary,
    _is_skipped_surface_url,
)
from kryon_core.surface.extract import has_double_slash_path  # noqa: E402
from kryon_core.surface.normalize import (  # noqa: E402
    is_port_in_path_artifact,
    normalize_bare_hostport_url,
)
from agentic_surface import (  # noqa: E402
    _extract_path_embedded_params,
    _extract_single_label_url_host,
    _fit_body_template_budget,
    _sanitize_json_template,
    apply_openapi_path_prefix,
    detect_internal_canonical_hosts,
    infer_openapi_mount_prefix,
    is_id_segment,
    is_loopback_or_private_base_url,
    is_non_endpoint_source_path,
    is_single_label_internal_host,
    is_virgin_state_sensitive_path,
    rewrite_internal_canonical_url,
    rewrite_internal_canonical_urls_in_text,
    route_template_of,
)
from target_bootstrap import (  # noqa: E402
    _normalize_excluded_pattern,
    _parse_out_of_scope_entry,
    _path_matches_excluded,
    check_dns_safety,
    is_destructive_lifecycle_route,
    is_logout_route,
    normalize_path,
)
from tech_routes import detect_tech  # noqa: E402

try:
    from kryon_core.surface.openapi import LocalSchema  # noqa: E402
except Exception:  # pragma: no cover - optional fallback
    LocalSchema = None  # type: ignore[assignment,misc]

try:
    from kryon_core.js.sourcemap import parse_source_map as _parse_source_map  # noqa: E402
except Exception:  # pragma: no cover - optional fallback
    _parse_source_map = None  # type: ignore[assignment]

try:
    import requests as _requests  # noqa: E402
except Exception:  # pragma: no cover - optional fallback
    _requests = None  # type: ignore[assignment]

try:
    from playwright.sync_api import sync_playwright as _sync_playwright  # type: ignore[import-not-found]

    _PW_IMPORT_OK = True
except Exception:  # pragma: no cover - optional dependency fallback
    _sync_playwright = None  # type: ignore[assignment]
    _PW_IMPORT_OK = False

HAS_PLAYWRIGHT: bool = bool(_BROWSER_HAS_PLAYWRIGHT and _PW_IMPORT_OK)

_ADMIN_ROLES = frozenset({"admin", "superadmin", "platform_admin", "tenant_admin", "owner", "root"})
_VALID_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_READONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_FORM_ALLOWED_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})
_NON_HTTP_SCHEMES = ("javascript:", "mailto:", "data:", "blob:", "tel:", "about:")

_DESTRUCTIVE_RE = re.compile(
    r"delete|remove|log[-_\s]?out|sign[-_\s]?out|pay|purchase|checkout|billing|"
    r"transfer|factory.?reset|reset|revoke|destroy|unsubscribe|cancel|deactivate|"
    r"wipe|purge|(?<![a-z])drop(?![a-z])|terminate|"
    r"reboot|restart|shut[-_\s]?down|power[-_\s]?off|(?<![a-z])(?:stop|kill)(?![a-z])",
    re.IGNORECASE,
)
_AUTH_FORM_RE = re.compile(
    r"login|log[-_]?in|sign[-_]?in|password|passwd|auth/token",
    re.IGNORECASE,
)
_AUTH_NAV_RE = re.compile(
    r"log[-_]?out|sign[-_]?out|log[-_]?in|sign[-_]?in",
    re.IGNORECASE,
)
_SAFE_PARAM_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-\[\]$:]{1,64}$")
_API_PATH_RE = re.compile(
    r"^/(?:api(?:/v\d+)?|v\d+|rest|rpc|graphql)(?:/|$)|/api(?:/v\d+)?/",
    re.IGNORECASE,
)
_VOLATILE_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_VOLATILE_HEX_RE = re.compile(r"\b[0-9a-f]{16,}\b", re.IGNORECASE)
_VOLATILE_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?\b"
)
_VOLATILE_NUM_RE = re.compile(r"\b\d+\b")

_BOUNDARY_RE = re.compile(r'boundary\s*=\s*(?:"([^"]+)"|([^\s;]+))', re.IGNORECASE)
_CD_LINE_RE = re.compile(rb"Content-Disposition\s*:\s*([^\r\n]+)", re.IGNORECASE)
_CD_NAME_RE = re.compile(r'(?:^|[;\s])name\s*=\s*(?:"([^"\r\n]{1,64})"|([^;\s\r\n]{1,64}))', re.IGNORECASE)
_CD_FILENAME_RE = re.compile(r"(?:^|[;\s])filename\*?\s*=", re.IGNORECASE)

_HEAVY_MEDIA_EXTS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".avif",
    ".bmp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".mp4",
    ".mp3",
    ".webm",
    ".ogg",
    ".wav",
    ".avi",
    ".mov",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
)
_LOW_SIGNAL_EXACT_PATHS = frozenset({"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"})
_SENSITIVE_PROBE_SEGMENTS = ("/.env", "/.git", "web.config", "phpinfo")
_HIGH_SIGNAL_PATH_KEYWORDS = (
    "upload",
    "download",
    "import",
    "export",
    "admin",
    "internal",
    "debug",
    "config",
    "graphql",
    "webhook",
    "proxy",
    "fetch",
    "redirect",
    "file",
    "render",
    "template",
    "search",
    "user",
    "account",
    "order",
    "note",
    "item",
)
_HIGH_SIGNAL_PARAM_NAMES = frozenset({
    "file",
    "filename",
    "filepath",
    "path",
    "url",
    "uri",
    "redirect",
    "next",
    "return",
    "return_to",
    "callback",
    "target",
    "dest",
    "template",
    "q",
    "query",
    "search",
    "id",
})

_ROOT_SPEC_PROBES: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
)
_API_PREFIXED_SPEC_PROBES: tuple[str, ...] = (
    "/api/v3/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
)
_STANDARD_NON_SPEC_MANIFEST_PROBES: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/info",
)
_STANDARD_MANIFEST_PROBES: tuple[str, ...] = (
    *_ROOT_SPEC_PROBES,
    *_STANDARD_NON_SPEC_MANIFEST_PROBES,
)
_BENIGN_TECH_PROBES: dict[str, tuple[str, ...]] = {
    "django": ("/api/schema", "/graphql"),
    "wordpress": ("/wp-json",),
    "spring": ("/v3/api-docs", "/actuator/info"),
    "rails": ("/rails/info",),
    "node": ("/graphql", "/api-docs"),
    "dotnet": ("/swagger/v1/swagger.json", "/swagger.json"),
    "php": ("/api",),
    "go": ("/api", "/metrics"),
}
_STANDARD_NON_AUTH_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "host",
    "origin",
    "referer",
    "user-agent",
    "connection",
    "cache-control",
})
_SAFE_OPENAPI_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_OPENAPI_SPEC_BYTES = 512 * 1024

_MAX_JS_CHUNKS = 96
_MAX_JS_CHUNK_BYTES = 1024 * 1024
_MAX_SOURCEMAPS_FETCHED = 4
_MAX_SOURCEMAP_BYTES = 1024 * 1024
_MAX_SOURCEMAP_FILES_PER_MAP = 24
_MAX_SOURCEMAP_CONTENT_CHARS = 128 * 1024
_MAX_SOURCEMAP_TOTAL_CHARS = 512 * 1024
_MAX_SIBLING_SPEC_PROBE_ORIGINS = 2
_MAX_OBSERVED_APP_HEADERS = 24
_MAX_OBSERVED_APP_HEADER_VALUE_CHARS = 256
_SIBLING_SPEC_PROBES: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/graphql",
)
_HIGH_SIGNAL_LAZY_CHUNK_KEYWORDS: tuple[str, ...] = (
    "admin",
    "auth",
    "account",
    "billing",
    "checkout",
    "order",
    "settings",
    "api",
    "graphql",
    "dashboard",
)
_SOURCEMAP_URL_RE = re.compile(
    r"""(?://|/\*)[@#][ \t]*sourceMappingURL=([^\s*'"`<>]+)""",
)
_INLINE_SOURCEMAP_DATA_RE = re.compile(
    r"""^data:application/json(?:;[a-z0-9_.\-+]+=[^;,]+)*;base64,([A-Za-z0-9+/=_-]+)$""",
    re.IGNORECASE,
)
_NEXT_DATA_SCRIPT_RE = re.compile(
    r"""<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["'][^>]*>([\s\S]*?)</script>""",
    re.IGNORECASE,
)
_LINK_TAG_RE = re.compile(r"<link\b([^>]+)>", re.IGNORECASE)
_LINK_REL_RE = re.compile(r"""\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)
_LINK_HREF_RE = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)
_LINK_AS_RE = re.compile(r"""\bas\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", re.IGNORECASE)
_NEXT_BUILD_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SORTED_PAGES_RE = re.compile(
    r"""sortedPages\s*:\s*\[((?:\s*(?:"[^"\\]{1,240}"|'[^'\\]{1,240}')\s*,?)*\s*)\]"""
)
_QUOTED_ROUTE_STR_RE = re.compile(r"""["'](/[A-Za-z0-9_.\-/\[\]:]+)["']""")
_BUILD_MANIFEST_ROUTE_KEY_RE = re.compile(
    r"""["'](/[A-Za-z0-9_.\-/\[\]]+)["']\s*:\s*\[((?:\s*(?:"[^"\\]{1,300}"|'[^'\\]{1,300}')\s*,?)*\s*)\]"""
)
_QUOTED_JS_CHUNK_RE = re.compile(
    r"""["'`]((?:/|https?://|static/|assets/|chunks/|_next/|_nuxt/|js/)?[A-Za-z0-9_.\-/\[\]]{1,240}\.(?:js|mjs|cjs))["'`]"""
)
_NEXT_DYNAMIC_SEG_RE = re.compile(r"\[{1,2}\.{0,3}([A-Za-z0-9_-]+)\]{1,2}")
_NEXT_INTERNAL_ROUTES: frozenset[str] = frozenset({"/_app", "/_error", "/_document", "/404", "/500"})

_SAFE_APP_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_APP_HEADER_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_APP_HEADER_SEP_RE = re.compile(r"[^a-z0-9]+")
_JWT_HEADER_VAL_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
_AWS_HEADER_VAL_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{12,}\b")
_KNOWN_SECRET_HEADER_VAL_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])(?:ghp_[A-Za-z0-9]{4,}|sk_live_[A-Za-z0-9]{4,}|xox[A-Za-z0-9-]{4,}|AIza[0-9A-Za-z_-]{6,})"
)
_EMAIL_HEADER_VAL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CANONICAL_APP_HEADERS: dict[str, str] = {
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
_STRIPPED_OBSERVED_APP_HEADERS: frozenset[str] = frozenset({
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
    "host",
    "content-type",
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
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    "x-amzn-trace-id",
    "x-cloud-trace-context",
    "purpose",
})
_STRIPPED_OBSERVED_HEADER_PREFIXES: tuple[str, ...] = ("sec-", "x-b3-", ":", "cf-", "x-amz-")
_SECRET_OBSERVED_HEADER_TOKENS: frozenset[str] = frozenset({
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
_SECRET_OBSERVED_HEADER_SUBSTRINGS: tuple[str, ...] = (
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
_MAX_STAGE0_SCRIPT_ASSETS = 160
_MAX_STAGE0_CDN_SCRIPT_ASSETS = 16
_MAX_CDN_JS_FULFILL_BYTES = 4 * 1024 * 1024
_MAX_DISCOVERED_API_HOSTS = 32
_MAX_API_HOST_SAMPLE_PATHS = 12
_MAX_SEO_ROUTES_PER_PATTERN = 6
_MAX_SEO_COLLECTOR_BUFFER = 64
_MAX_SEO_BFS_VISITS_PER_PATTERN = 2
_MAX_SEO_DISCOVERY_HINTS = 2
_CDN_STRIPPED_AUTH_HEADERS: frozenset[str] = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-csrftoken",
    "x-xsrf-token",
    "xsrf-token",
    "csrf-token",
    "x-session-id",
    "x-session-token",
})
_THIRD_PARTY_TRACKER_DOMAINS: frozenset[str] = frozenset({
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "googlesyndication.com",
    "googleadservices.com",
    "adservice.google.com",
    "doubleclick.net",
    "connect.facebook.net",
    "facebook.com",
    "facebook.net",
    "hotjar.com",
    "clarity.ms",
    "mixpanel.com",
    "mxpnl.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "heapanalytics.com",
    "fullstory.com",
    "logrocket.com",
    "sentry.io",
    "sentry-cdn.com",
    "datadoghq.com",
    "datadoghq-browser-agent.com",
    "browser-intake-datadoghq.com",
    "newrelic.com",
    "nr-data.net",
    "bugsnag.com",
    "rollbar.com",
    "tiktok.com",
    "twitter.com",
    "ads-twitter.com",
    "t.co",
    "linkedin.com",
    "licdn.com",
    "bing.com",
    "yandex.ru",
    "yandex.com",
    "criteo.com",
    "criteo.net",
    "insider.com",
    "useinsider.com",
    "onesignal.com",
    "zdassets.com",
    "zendesk.com",
    "intercom.io",
    "intercomcdn.com",
    "recaptcha.net",
    "gstatic.com",
    "google.com",
    "hcaptcha.com",
    "challenges.cloudflare.com",
    "cloudflareinsights.com",
    "optimizely.com",
    "launchdarkly.com",
    "cookiebot.com",
    "onetrust.com",
    "cookielaw.org",
    "snapchat.com",
    "sc-static.net",
    "taboola.com",
    "outbrain.com",
    "quantserve.com",
    "scorecardresearch.com",
    "braze.com",
    "appboycdn.com",
    "branch.io",
    "adjust.com",
    "appsflyer.com",
    "hubspot.com",
    "hs-analytics.net",
    "hs-scripts.com",
    "hsforms.net",
    "demdex.net",
    "omtrdc.net",
    "2o7.net",
    "adnxs.com",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "casalemedia.com",
    "crisp.chat",
    "tawk.to",
    "livechatinc.com",
})
_KNOWN_NON_API_DOC_HOSTS: frozenset[str] = frozenset({
    "w3.org",
    "schema.org",
    "reactjs.org",
    "react.dev",
    "vuejs.org",
    "nuxt.com",
    "nuxtjs.org",
    "nextjs.org",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "npmjs.org",
    "npmjs.com",
    "mozilla.org",
    "stackoverflow.com",
    "wikipedia.org",
    "opensource.org",
    "creativecommons.org",
    "apache.org",
    "gnu.org",
    "ietf.org",
    "whatwg.org",
    "typescriptlang.org",
    "webpack.js.org",
    "vitejs.dev",
    "babeljs.io",
    "axios-http.com",
    "lodash.com",
    "momentjs.com",
    "example.org",
    "example.net",
})
_MULTI_LABEL_CC_SLDS: frozenset[str] = frozenset({
    "co",
    "com",
    "net",
    "org",
    "gov",
    "edu",
    "ac",
    "mil",
    "ne",
    "or",
})
_STATIC_CDN_SUBDOMAIN_PREFIXES: frozenset[str] = frozenset({
    "cdn",
    "img",
    "images",
    "image",
    "media",
    "static",
    "assets",
    "asset",
    "js",
    "css",
    "font",
    "fonts",
    "video",
    "videos",
    "thumb",
    "thumbs",
})
_API_SUBDOMAIN_HINTS: frozenset[str] = frozenset({
    "api",
    "bff",
    "sfapi",
    "auth",
    "oauth",
    "sso",
    "login",
    "account",
    "accounts",
    "gateway",
    "gw",
    "graphql",
    "rest",
    "rpc",
    "backend",
    "service",
    "services",
    "edge",
    "app",
    "checkout",
    "cart",
    "payment",
    "payments",
    "order",
    "orders",
    "search",
    "user",
    "users",
    "member",
    "members",
    "identity",
    "idp",
    "token",
})
_SEO_CATEGORY_K_RE = re.compile(r"^.+-[kK]-[kK]\d+$")
_SEO_PRODUCT_P_RE = re.compile(r"^.+-[pP]-[A-Za-z0-9]{4,}$")
_SEO_CATALOG_C_RE = re.compile(r"^.+-[cC]-\d+$")
_SEO_UUID_SEG_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_NON_SEO_FUNCTIONAL_SEGMENTS: frozenset[str] = frozenset({
    "api",
    "graphql",
    "rest",
    "rpc",
    "login",
    "signin",
    "sign-in",
    "signup",
    "sign-up",
    "register",
    "auth",
    "oauth",
    "sso",
    "token",
    "session",
    "account",
    "accounts",
    "hesabim",
    "profile",
    "user",
    "users",
    "order",
    "orders",
    "siparis",
    "siparislerim",
    "cart",
    "sepet",
    "checkout",
    "payment",
    "payments",
    "odeme",
    "billing",
    "admin",
    "dashboard",
    "settings",
    "ayarlar",
    "upload",
    "download",
    "export",
    "import",
    "webhook",
    "callback",
    "redirect",
    "proxy",
    "search",
    "ara",
    "health",
    "status",
    "openapi",
    "swagger",
    "api-docs",
    "ws",
    "wss",
})
_NON_SEO_SLUG_TOKENS: frozenset[str] = frozenset({
    "login",
    "signin",
    "signup",
    "register",
    "auth",
    "oauth",
    "sso",
    "logout",
    "password",
    "forgot",
    "reset",
    "admin",
    "graphql",
    "openapi",
    "swagger",
    "webhook",
    "callback",
    "upload",
    "download",
    "import",
    "export",
    "account",
    "hesabim",
    "checkout",
    "billing",
})
_ABS_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>`\\)}\]]+", re.IGNORECASE)
_JS_FETCH_ABS_URL_RE = re.compile(
    r"""\bfetch\s*\(\s*(['"`])(https?://[^'"`\s]+)\1""",
    re.IGNORECASE,
)
_JS_AXIOS_METHOD_ABS_URL_RE = re.compile(
    r"""\baxios\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*(['"`])(https?://[^'"`\s]+)\2""",
    re.IGNORECASE,
)
_JS_FETCH_METHOD_OPT_RE = re.compile(
    r"""\bmethod\s*:\s*(['"])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\1""",
    re.IGNORECASE,
)
_SCRIPT_ASSET_EXTS = (".js", ".mjs", ".cjs", ".wasm")
_SCRIPT_BUNDLE_PATH_MARKERS = (
    "/_app/immutable/",
    "/_next/static/",
    "/@vite/",
    "/@fs/",
    "/@id/",
    "/node_modules/",
    "/static/js/",
    "/assets/js/",
)
_STAGE0_BUNDLER_NOISE_MARKERS = (
    "/_app/immutable/",
    "/_next/static/",
)
_ROUTE_GROUP_SEG_RE = re.compile(r"^\([^/()]+\)$")
_MAX_HTML_DOCS = 64
_MAX_HTML_BYTES = 256 * 1024
_MAX_CSS_DOCS = 24
_MAX_CSS_BYTES = 128 * 1024
_MAX_PARAMS_PER_ROUTE = 32
_MAX_ROUTES_RETURNED = 200
_MAX_DISCOVERY_HINTS = 12
_MAX_REPS_PER_CLUSTER = 2
_MAX_VISITS_PER_TEMPLATE = 2

# Minimal valid 1x1 transparent PNG payload for synthetic image uploads.
_TINY_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)

_COLLECT_DOM_STATE_JS = r"""() => {
  const controls = [];
  const controlEls = [];
  const forms = [];
  const formEls = [];
  const standaloneFiles = [];
  const standaloneFileEls = [];
  const links = [];
  const canonicalLinks = [];
  const hashRoutes = [];
  const headings = [];
  const visibleLinks = [];
  let dialogCount = 0;

  const isVisible = (el) => {
    if (!el || !el.getBoundingClientRect) return false;
    try {
      const style = window.getComputedStyle(el);
      if (!style || style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
        return false;
      }
    } catch (_) {}
    const rect = el.getBoundingClientRect();
    return (rect.width > 0 && rect.height > 0);
  };

  const pushHref = (raw) => {
    const val = String(raw || '').trim();
    if (!val) return;
    const low = val.toLowerCase();
    if (
      low.startsWith('javascript:')
      || low.startsWith('mailto:')
      || low.startsWith('data:')
      || low.startsWith('blob:')
      || low.startsWith('tel:')
      || low.startsWith('about:')
    ) {
      return;
    }
    if (val.startsWith('#/')) {
      if (hashRoutes.length < 120) hashRoutes.push(val);
      return;
    }
    if (val.startsWith('#')) return;
    if (links.length < 240) links.push(val);
  };

  const walk = (root) => {
    if (!root || !root.querySelectorAll) return;

    for (const el of root.querySelectorAll('link[rel][href]')) {
      const rel = String(el.getAttribute('rel') || '').toLowerCase().split(/\s+/);
      if (rel.includes('canonical') && canonicalLinks.length < 4) {
        const chref = String(el.getAttribute('href') || '').trim();
        if (chref) canonicalLinks.push(chref);
      }
    }
    for (const el of root.querySelectorAll('a[href], area[href]')) {
      const href = el.getAttribute('href');
      pushHref(href);
      if (isVisible(el) && href && visibleLinks.length < 80) {
        visibleLinks.push(String(href).slice(0, 120));
      }
    }
    for (const el of root.querySelectorAll('frame[src], iframe[src]')) {
      pushHref(el.getAttribute('src'));
    }
    for (const el of root.querySelectorAll('[data-href], [data-route], [data-hash]')) {
      for (const attr of ['data-href', 'data-route', 'data-hash']) {
        const val = el.getAttribute(attr);
        if (val) pushHref(val);
      }
    }

    for (const el of root.querySelectorAll('dialog[open], [role="dialog"], [aria-modal="true"]')) {
      if (isVisible(el)) dialogCount += 1;
    }

    for (const el of root.querySelectorAll('h1, h2, h3, [role="heading"]')) {
      if (!isVisible(el)) continue;
      if (headings.length < 40) {
        const tag = String(el.tagName || 'h').toLowerCase();
        const txt = String(el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        headings.push({tag, text: txt});
      }
    }

    for (const form of root.querySelectorAll('form')) {
      const vis = isVisible(form);
      const fields = [];
      const submitTexts = [];
      for (const inp of form.querySelectorAll('input, textarea, select')) {
        const tag = String(inp.tagName || '').toLowerCase();
        const typ = tag === 'input' ? String(inp.getAttribute('type') || 'text').toLowerCase() : tag;
        if (typ === 'submit' || typ === 'button' || typ === 'reset' || typ === 'image') {
          if (typ === 'submit') {
            submitTexts.push(String(inp.getAttribute('value') || inp.getAttribute('aria-label') || '').trim());
          }
          continue;
        }
        const name = String(inp.getAttribute('name') || inp.id || '').trim();
        fields.push({
          name,
          type: typ,
          tag,
          accept: String(inp.getAttribute('accept') || '').trim().slice(0, 80),
          required: !!inp.required,
          disabled: !!inp.disabled,
          min: String(inp.getAttribute('min') || '').trim().slice(0, 32),
          visible: isVisible(inp),
        });
      }
      for (const btn of form.querySelectorAll('button')) {
        const btyp = String(btn.getAttribute('type') || 'submit').toLowerCase();
        if (btyp === 'submit' || !btn.hasAttribute('type')) {
          submitTexts.push(String(btn.textContent || btn.getAttribute('aria-label') || '').trim());
        }
      }
      const idx = formEls.length;
      formEls.push(form);
      forms.push({
        form_index: idx,
        action: String(form.getAttribute('action') || '').trim(),
        method: String(form.getAttribute('method') || 'GET').trim().toUpperCase(),
        enctype: String(form.getAttribute('enctype') || '').trim(),
        id: String(form.id || '').trim().slice(0, 80),
        name: String(form.getAttribute('name') || '').trim().slice(0, 80),
        aria_label: String(form.getAttribute('aria-label') || '').trim().slice(0, 80),
        text: submitTexts.join(' ').replace(/\s+/g, ' ').trim().slice(0, 160),
        visible: vis,
        fields: fields.slice(0, 32),
      });
    }

    for (const finp of root.querySelectorAll('input[type="file"]')) {
      if (finp.closest && finp.closest('form')) continue;
      if (finp.disabled) continue;
      const idx = standaloneFileEls.length;
      standaloneFileEls.push(finp);
      standaloneFiles.push({
        file_index: idx,
        name: String(finp.getAttribute('name') || finp.id || 'file').trim().slice(0, 64),
        id: String(finp.id || '').trim().slice(0, 64),
        accept: String(finp.getAttribute('accept') || '').trim().slice(0, 80),
        aria_label: String(finp.getAttribute('aria-label') || '').trim().slice(0, 80),
        visible: isVisible(finp),
      });
    }

    const seenCtrl = new WeakSet();
    const ctrlSelector = [
      '[role="tab"]',
      '[role="menuitem"]',
      'button[aria-controls]',
      'button[aria-expanded]',
      'button[aria-haspopup]',
      '[role="button"]',
      'summary',
      'button',
      'input[type="button"]',
      'nav a',
      'aside a',
      '[role="navigation"] a',
    ].join(', ');
    for (const el of root.querySelectorAll(ctrlSelector)) {
      if (seenCtrl.has(el)) continue;
      seenCtrl.add(el);
      if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
      if (!isVisible(el)) continue;
      const tag = String(el.tagName || '').toLowerCase();
      const role = String(el.getAttribute('role') || '').toLowerCase();
      const btnType = tag === 'button' ? String(el.getAttribute('type') || '').toLowerCase() : '';
      if (tag === 'button' && btnType === 'reset') continue;
      const inForm = !!(el.closest && el.closest('form'));
      const isNavControl = (
        role === 'tab'
        || role === 'menuitem'
        || el.hasAttribute('aria-controls')
        || el.hasAttribute('aria-expanded')
        || el.hasAttribute('aria-haspopup')
        || tag === 'summary'
      );
      if (inForm && (!isNavControl || btnType === 'submit' || (tag === 'button' && !btnType))) {
        continue;
      }
      if (tag === 'a') {
        const rawHref = String(el.getAttribute('href') || '').trim();
        const lowHref = rawHref.toLowerCase();
        const isNonNavHref = (
          !rawHref
          || (rawHref.startsWith('#') && !rawHref.startsWith('#/'))
          || lowHref.startsWith('javascript:')
        );
        const hasInteractiveAttr = (
          role === 'button'
          || role === 'tab'
          || role === 'menuitem'
          || el.hasAttribute('aria-controls')
          || el.hasAttribute('aria-expanded')
          || el.hasAttribute('aria-haspopup')
          || el.hasAttribute('onclick')
        );
        if (!isNonNavHref && !hasInteractiveAttr) {
          continue;
        }
      }
      if (controls.length >= 60) break;
      const idx = controlEls.length;
      controlEls.push(el);
      const titleAttr = String(el.getAttribute('title') || '').trim();
      const tooltipAttr = String(
        el.getAttribute('data-tooltip')
        || el.getAttribute('data-title')
        || el.getAttribute('data-testid')
        || ''
      ).trim();
      const label = String(
        el.getAttribute('aria-label')
        || el.textContent
        || titleAttr
        || tooltipAttr
        || el.getAttribute('value')
        || el.id
        || el.getAttribute('name')
        || ''
      ).replace(/\s+/g, ' ').trim().slice(0, 80);
      const classHint = typeof el.className === 'string'
        ? el.className.replace(/\s+/g, ' ').trim().slice(0, 80)
        : '';
      const inNavContainer = !!(
        el.closest && el.closest(
          'nav, aside, header, [role="navigation"], [role="tablist"], [role="menubar"], [role="toolbar"], [class*="sidebar"], [class*="side-bar"], [class*="menu"], [class*="drawer"]'
        )
      );
      const navTrigger = Boolean(
        isNavControl
        || role === 'button'
        || inNavContainer
        || /sidebar|side-bar|menu|drawer|panel|tab|manager|toggle/i.test(
          `${label} ${titleAttr} ${tooltipAttr} ${String(el.id || '')} ${classHint}`
        )
      );
      controls.push({
        ctrl_index: idx,
        tag,
        role,
        id: String(el.id || '').trim().slice(0, 64),
        name: String(el.getAttribute('name') || '').trim().slice(0, 64),
        aria_controls: String(el.getAttribute('aria-controls') || '').trim().slice(0, 64),
        aria_selected: String(el.getAttribute('aria-selected') || '').trim().toLowerCase(),
        aria_expanded: String(el.getAttribute('aria-expanded') || '').trim().toLowerCase(),
        label,
        title: titleAttr.slice(0, 80),
        tooltip: tooltipAttr.slice(0, 80),
        class_hint: classHint,
        nav_trigger: navTrigger,
        in_form: inForm,
        onclick: String(el.getAttribute('onclick') || '').trim().slice(0, 120),
      });
    }

    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };

  walk(document);
  window.__kryonStage0 = {
    controls: controlEls,
    forms: formEls,
    standaloneFiles: standaloneFileEls,
  };
  const baseEl = document.querySelector('base[href]');
  const baseHref = baseEl ? String(baseEl.getAttribute('href') || '').trim() : '';
  return {
    url: String(window.location.href || ''),
    base_uri: String(document.baseURI || window.location.href || ''),
    base_href: baseHref,
    canonical_links: canonicalLinks,
    pathname: String(window.location.pathname || '/'),
    hash: String(window.location.hash || ''),
    title: String(document.title || '').slice(0, 120),
    links,
    hash_routes: hashRoutes,
    forms,
    standalone_files: standaloneFiles,
    controls,
    headings,
    dialog_count: dialogCount,
    visible_links: visibleLinks,
  };
}"""


@dataclass
class _RouteRecord:
    """In-memory candidate route collected across all Stage 0 layers."""

    method: str
    path: str
    origin: str = ""
    params: set[str] = field(default_factory=set)
    is_form: bool = False
    best_status: int = 0
    body_template: dict[str, Any] | None = None
    body_template_observed: bool = False
    multipart_fields: set[str] = field(default_factory=set)
    multipart_files: set[str] = field(default_factory=set)
    first_seen: int = 0

    @property
    def export_url(self) -> str:
        return f"{self.origin}{self.path}" if self.origin else self.path


@dataclass
class _ExternalAPIHostRecord:
    """Observed non-tracker external or sibling API origin and sample paths."""

    origin: str
    host: str
    same_registrable_domain: bool
    methods: set[str] = field(default_factory=set)
    sample_paths: list[str] = field(default_factory=list)
    observation_count: int = 0


class _Stage0Budget:
    """Thread-safe Stage 0 budget slice backed by ``AgenticHTTPClient.budget``."""

    def __init__(self, http_client: AgenticHTTPClient, cap: int, *, reserve: int = 0) -> None:
        self._http = http_client
        self.cap = max(0, int(cap))
        self.reserve = max(0, min(self.cap, int(reserve)))
        self.charged = 0
        self.global_exhausted = False
        self._lock = threading.Lock()

    def remaining(self, *, include_reserve: bool = False) -> int:
        with self._lock:
            effective_cap = self.cap if include_reserve else max(0, self.cap - self.reserve)
            slice_left = max(0, effective_cap - self.charged)
        return min(slice_left, _budget_remaining(self._http))

    def can_spend(self, *, include_reserve: bool = False) -> bool:
        return self.remaining(include_reserve=include_reserve) > 0

    def try_consume(self, *, include_reserve: bool = False) -> bool:
        with self._lock:
            effective_cap = self.cap if include_reserve else max(0, self.cap - self.reserve)
            if self.charged >= effective_cap:
                return False
            allowed, _reason = self._http.budget.consume()
            if not allowed:
                self.global_exhausted = True
                return False
            self.charged += 1
            return True

    def account_external(self, delta: int) -> None:
        if delta <= 0:
            return
        with self._lock:
            self.charged += int(delta)


def _empty_result(
    base_url: str,
    *,
    status: str,
    mode: str,
    actors_crawled: Sequence[str] = (),
    elapsed_seconds: float = 0.0,
) -> dict[str, Any]:
    actors_list = list(actors_crawled)
    stats: dict[str, Any] = {
        "status": status,
        "mode": mode,
        "actors_crawled": list(actors_list),
        "pages_visited": 0,
        "dom_states_seen": 0,
        "ui_actions_taken": 0,
        "forms_submitted": 0,
        "uploads_triggered": 0,
        "network_requests_captured": 0,
        "js_chunks_parsed": 0,
        "cdn_js_chunks_parsed": 0,
        "source_maps_parsed": 0,
        "lazy_chunks_discovered": 0,
        "passive_probes_sent": 0,
        "probed_paths": [],
        "discovered_auth_headers": [],
        "external_api_hosts_seen": 0,
        "ws_endpoints_found": 0,
        "routes_accepted": 0,
        "body_templates_count": 0,
        "multipart_schemas_count": 0,
        "requests_charged": 0,
        "elapsed_seconds": round(float(elapsed_seconds), 3),
    }
    return {
        "schema": "stage0-seed/1",
        "url": base_url,
        "status": status,
        "mode": mode,
        "actors_crawled": actors_list,
        "links": [],
        "forms": [],
        "ws_endpoints": [],
        "body_templates": {},
        "multipart_schemas": {},
        "auth_headers": [],
        "observed_app_headers": {},
        "discovered_api_hosts": [],
        "discovery_hints": [],
        "seed_file": "",
        "stats": stats,
    }


def _scoped_storage_key(url: str, base_url: str, *, include_query: bool = False) -> str:
    """Return ``/path`` for primary-origin URLs or ``scheme://netloc/path`` for sibling origins."""
    raw = str(url or "").strip()
    if not raw:
        return "/"
    parsed = urlsplit(raw)
    try:
        norm_p = normalize_path(parsed.path or "/")
    except ValueError:
        norm_p = parsed.path or "/"
    path_key = f"{norm_p}?{parsed.query}" if (include_query and parsed.query) else norm_p
    url_parts = _normalized_origin_parts(raw)
    base_parts = _normalized_origin_parts(base_url)
    if (
        url_parts is not None
        and base_parts is not None
        and url_parts[:3] != base_parts[:3]
    ):
        return f"{url_parts[3]}{path_key}"
    return path_key


def _sanitize_observed_app_headers(
    raw_headers: dict[str, Any],
    *,
    blocked_names: set[str] | frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Extract non-secret, non-boilerplate XHR app headers from observed browser requests."""
    if not isinstance(raw_headers, dict) or not raw_headers:
        return {}
    cleaned: dict[str, str] = {}
    for raw_k, raw_v in raw_headers.items():
        if not isinstance(raw_k, str) or raw_v is None:
            continue
        name = raw_k.strip()
        if not name or not _SAFE_APP_HEADER_NAME_RE.fullmatch(name):
            continue
        low = name.lower()
        if low in _STRIPPED_OBSERVED_APP_HEADERS or low in blocked_names:
            continue
        if any(low.startswith(prefix) for prefix in _STRIPPED_OBSERVED_HEADER_PREFIXES):
            continue
        split_camel = _APP_HEADER_CAMEL_RE.sub(r"\1_\2", name)
        snake = _APP_HEADER_SEP_RE.sub("_", split_camel.lower()).strip("_")
        tokens = tuple(tok for tok in snake.split("_") if tok)
        if snake in _SECRET_OBSERVED_HEADER_TOKENS or any(tok in _SECRET_OBSERVED_HEADER_TOKENS for tok in tokens):
            continue
        if any(sub in snake for sub in _SECRET_OBSERVED_HEADER_SUBSTRINGS):
            continue
        # Only capture recognized app headers or explicit X-* custom app headers.
        if low not in _CANONICAL_APP_HEADERS and not low.startswith("x-"):
            continue
        val = str(raw_v).strip()
        if (
            not val
            or len(val) > _MAX_OBSERVED_APP_HEADER_VALUE_CHARS
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in val)
        ):
            continue
        val_low = val.lower()
        if (
            "<redacted" in val_low
            or val_low.startswith(("bearer ", "basic ", "digest ", "token ", "aws4-hmac-sha256"))
            or "aws4-hmac-sha256" in val_low
            or "-----begin " in val_low
            or "-----end " in val_low
            or _JWT_HEADER_VAL_RE.search(val)
            or _AWS_HEADER_VAL_RE.search(val)
            or _KNOWN_SECRET_HEADER_VAL_RE.search(val)
            or _EMAIL_HEADER_VAL_RE.search(val)
            or (";" in val and "=" in val)
        ):
            continue
        if low in _CANONICAL_APP_HEADERS:
            canon_name = _CANONICAL_APP_HEADERS[low]
        elif name.islower():
            canon_name = "-".join(part.capitalize() for part in name.split("-"))
        else:
            canon_name = name
        cleaned[canon_name] = val
        if len(cleaned) >= _MAX_OBSERVED_APP_HEADERS:
            break
    return cleaned


def _is_explicitly_excluded_by_scope(scope_guard: Any, raw_url: str) -> bool:
    """Return True if ``raw_url`` matches ``scope_guard`` out-of-scope assets or excluded paths."""
    if scope_guard is None:
        return False
    origin_parts = _normalized_origin_parts(raw_url)
    if origin_parts is None:
        return True
    scheme, host, port, _orig = origin_parts
    parsed = urlsplit(str(raw_url or "").strip())
    try:
        norm_path_lower = normalize_path(parsed.path or "/").lower()
    except ValueError:
        return True

    excluded_paths = getattr(scope_guard, "excluded_paths", ()) or ()
    for pattern in excluded_paths:
        pat_str = str(pattern or "").strip().lower()
        if pat_str and _path_matches_excluded(norm_path_lower, pat_str):
            return True

    out_origin_rules = getattr(scope_guard, "_out_of_scope_origin_rules", None)
    out_path_rules = getattr(scope_guard, "_out_of_scope_path_rules", None)
    if out_origin_rules is not None or out_path_rules is not None:
        for rule in out_origin_rules or ():
            if rule.matches_origin(scheme, host, port):
                return True
        for rule, path_pattern in out_path_rules or ():
            if rule.matches_origin(scheme, host, port) and _path_matches_excluded(norm_path_lower, path_pattern):
                return True
        return False

    for entry in getattr(scope_guard, "out_of_scope_assets", ()) or ():
        try:
            kind, rule, norm_pat = _parse_out_of_scope_entry(
                entry,
                allow_prose=True,
                allow_path=True,
                label="out_of_scope_assets",
            )
        except ValueError:
            return True
        if kind == "path" and norm_pat is not None:
            if _path_matches_excluded(norm_path_lower, norm_pat):
                return True
        elif kind == "asset" and rule is not None and rule.matches_origin(scheme, host, port):
            if rule.path in {"", "/"}:
                return True
            if _path_matches_excluded(norm_path_lower, _normalize_excluded_pattern(rule.path)):
                return True
    return False


def _is_allowed_cdn_sourcemap_url(
    map_url: str,
    base_url: str,
    *,
    referrer_url: str = "",
    scope_guard: Any = None,
    resolve_dns: bool = True,
    fail_closed_on_dns_error: bool = False,
) -> bool:
    """Return True strictly for safe, read-only, non-tracker, public cross-origin CDN .map URLs."""
    origin_parts = _normalized_origin_parts(map_url)
    if origin_parts is None:
        return False
    req_scheme, req_host, req_port, _req_origin = origin_parts
    base_parts = _normalized_origin_parts(base_url)
    if base_parts is not None and (req_scheme, req_host, req_port) == base_parts[:3]:
        return False
    if scope_guard is not None and _is_explicitly_excluded_by_scope(scope_guard, map_url):
        return False
    if str(referrer_url or "").strip():
        ref_parts = _normalized_origin_parts(referrer_url)
        if ref_parts is None or (req_scheme, req_host, req_port) != ref_parts[:3]:
            return False
    # ALWAYS reject loopback, private, link-local, CGNAT, multicast, reserved, unspecified,
    # and internal hosts regardless of whether base_url is loopback/private.
    if _is_link_local_metadata_host(req_host) or _is_non_public_or_internal_host(req_host):
        return False
    if _is_tracker_or_telemetry_host(req_host):
        return False
    parsed = urlsplit(str(map_url or "").strip())
    path = parsed.path or "/"
    low_path = path.lower()
    if (
        not low_path.endswith(".map")
        or _API_PATH_RE.search(low_path)
        or _extract_path_embedded_params(path)
        or is_destructive_lifecycle_route(path)
        or is_logout_route(path)
    ):
        return False
    if resolve_dns:
        try:
            check_dns_safety(req_host, req_port)
        except ValueError:
            return False
        except OSError:
            if fail_closed_on_dns_error:
                return False
    return True


def _normalize_inline_sourcemap_b64(raw_b64: str) -> str:
    """Normalize standard or URL-safe Base64 inline source map payload with proper ``=`` padding."""
    cleaned = str(raw_b64 or "").strip().replace("-", "+").replace("_", "/")
    if not cleaned:
        return ""
    rem = len(cleaned) % 4
    if rem == 1:
        return ""
    if rem:
        cleaned += "=" * (4 - rem)
    return cleaned


def _extract_sourcemap_references(js_text: str, js_url: str) -> dict[str, list[str]]:
    """Extract inline base64 and resolved external ``//# sourceMappingURL=...`` references."""
    inline_refs: list[str] = []
    external_refs: list[str] = []
    seen_inline: set[str] = set()
    seen_external: set[str] = set()
    text = str(js_text or "")
    if not text or "sourceMappingURL" not in text:
        return {"inline": inline_refs, "external": external_refs}

    for match in _SOURCEMAP_URL_RE.finditer(text):
        raw_ref = str(match.group(1) or "").strip().rstrip(";,)")
        if not raw_ref or "${" in raw_ref:
            continue
        m_inline = _INLINE_SOURCEMAP_DATA_RE.fullmatch(raw_ref)
        if m_inline:
            norm_b64 = _normalize_inline_sourcemap_b64(m_inline.group(1))
            if not norm_b64:
                continue
            norm_uri = f"data:application/json;base64,{norm_b64}"
            if norm_uri not in seen_inline and len(inline_refs) < 4:
                seen_inline.add(norm_uri)
                inline_refs.append(norm_uri)
            continue
        if "+" in raw_ref:
            continue
        if raw_ref.lower().startswith(_NON_HTTP_SCHEMES) or raw_ref.startswith("//"):
            continue
        resolved = urljoin(str(js_url or ""), raw_ref)
        if resolved.lower().startswith(("http://", "https://")):
            parsed_r = urlsplit(resolved)
            if (parsed_r.path or "").lower().endswith(".map"):
                clean_r = urlunsplit((parsed_r.scheme.lower(), parsed_r.netloc, parsed_r.path, parsed_r.query, ""))
                if clean_r not in seen_external and len(external_refs) < 8:
                    seen_external.add(clean_r)
                    external_refs.append(clean_r)
    return {"inline": inline_refs, "external": external_refs}


def _normalize_spa_route_candidate(raw_route: str) -> str:
    """Convert Next.js/Nuxt dynamic route patterns (``[id]``/``[...slug]``/``[[...slug]]``) into normalized route paths."""
    cand = str(raw_route or "").strip()
    if not cand or not cand.startswith("/") or cand.startswith("//"):
        return ""
    if any(ch.isspace() for ch in cand) or len(cand) > 180:
        return ""
    if cand in _NEXT_INTERNAL_ROUTES or cand.startswith("/_next/"):
        return ""
    cand = _NEXT_DYNAMIC_SEG_RE.sub(r"{\1}", cand)
    try:
        norm = normalize_path(cand)
    except ValueError:
        return ""
    if is_static_asset_url(norm) or is_non_endpoint_source_path(norm):
        return ""
    return norm


def _extract_lazy_spa_routes_and_chunks(
    html_or_js_text: str,
    *,
    doc_url: str,
    base_url: str,
) -> dict[str, list[str]]:
    """Extract Next.js/Vite/Webpack/Nuxt lazy SPA routes, manifests, and high-signal chunk paths."""
    routes: list[str] = []
    chunks: list[str] = []
    manifests: list[str] = []
    seen_routes: set[str] = set()
    seen_chunks: set[str] = set()
    seen_manifests: set[str] = set()

    text = str(html_or_js_text or "")
    if not text:
        return {"routes": routes, "chunks": chunks, "manifests": manifests}

    resolve_base = str(doc_url or base_url or "").strip()
    is_next_context = bool(
        "__NEXT_DATA__" in text
        or "__BUILD_MANIFEST" in text
        or "_next/static/" in text
        or "/_next/" in resolve_base.lower()
        or "_buildmanifest.js" in resolve_base.lower()
    )

    def _add_route(raw_r: str) -> None:
        norm_r = _normalize_spa_route_candidate(raw_r)
        if norm_r and norm_r not in seen_routes and len(routes) < 120:
            seen_routes.add(norm_r)
            routes.append(norm_r)

    def _resolve_chunk_ref(raw_c: str, *, next_manifest_relative: bool = False) -> str:
        c = str(raw_c or "").strip()
        if not c or c.lower().startswith(_NON_HTTP_SCHEMES) or c.startswith("//"):
            return ""
        if c.startswith("static/") and (next_manifest_relative or is_next_context):
            c = f"/_next/{c}"
        elif not c.startswith(("/", "http://", "https://")):
            c = urljoin(resolve_base, c) if resolve_base else "/" + c
        return c

    def _add_chunk(raw_c: str, *, next_manifest_relative: bool = False) -> None:
        norm_c = _resolve_chunk_ref(raw_c, next_manifest_relative=next_manifest_relative)
        if norm_c and norm_c not in seen_chunks and len(chunks) < 120:
            seen_chunks.add(norm_c)
            chunks.append(norm_c)

    def _add_manifest(raw_m: str) -> None:
        norm_m = _resolve_chunk_ref(raw_m, next_manifest_relative=True)
        if norm_m and norm_m not in seen_manifests and len(manifests) < 8:
            seen_manifests.add(norm_m)
            manifests.append(norm_m)
            _add_chunk(norm_m, next_manifest_relative=True)

    # 1. Next.js __NEXT_DATA__ script JSON
    for nm in _NEXT_DATA_SCRIPT_RE.finditer(text):
        raw_json = (nm.group(1) or "").strip()
        if not raw_json or len(raw_json) > 512 * 1024:
            continue
        try:
            next_data = json.loads(raw_json)
        except ValueError:
            continue
        if not isinstance(next_data, dict):
            continue
        page_val = next_data.get("page")
        if isinstance(page_val, str):
            _add_route(page_val)
        build_id = str(next_data.get("buildId") or "").strip()
        if build_id and _NEXT_BUILD_ID_RE.fullmatch(build_id):
            _add_manifest(f"/_next/static/{build_id}/_buildManifest.js")

    # 2. Next.js _buildManifest.js sortedPages & route chunk map
    for sp_match in _SORTED_PAGES_RE.finditer(text):
        for r_match in _QUOTED_ROUTE_STR_RE.finditer(sp_match.group(1)):
            _add_route(r_match.group(1))
    if "__BUILD_MANIFEST" in text or "sortedPages" in text:
        for bm_match in _BUILD_MANIFEST_ROUTE_KEY_RE.finditer(text):
            _add_route(bm_match.group(1))
            for cm in _QUOTED_JS_CHUNK_RE.finditer(bm_match.group(2)):
                _add_chunk(cm.group(1), next_manifest_relative=True)

    # 3. <link rel="modulepreload" href="..."> / script preload chunks (Vite / Nuxt / ESM)
    if "<link" in text.lower():
        for lm in _LINK_TAG_RE.finditer(text):
            attrs = lm.group(1) or ""
            rel_m = _LINK_REL_RE.search(attrs)
            if not rel_m:
                continue
            rel_val = (rel_m.group(1) or rel_m.group(2) or rel_m.group(3) or "").lower()
            rel_tokens = set(rel_val.split())
            is_mod_preload = "modulepreload" in rel_tokens
            if not is_mod_preload and "preload" in rel_tokens:
                as_m = _LINK_AS_RE.search(attrs)
                as_val = (as_m.group(1) or as_m.group(2) or as_m.group(3) or "").lower() if as_m else ""
                is_mod_preload = as_val == "script"
            if not is_mod_preload:
                continue
            href_m = _LINK_HREF_RE.search(attrs)
            if not href_m:
                continue
            href_val = (href_m.group(1) or href_m.group(2) or href_m.group(3) or "").strip()
            if href_val:
                _add_chunk(href_val)

    # 4. Webpack / Vite / Nuxt chunk path strings referencing high-signal modules
    scan_text = text[:_MAX_JS_CHUNK_BYTES]
    for cm in _QUOTED_JS_CHUNK_RE.finditer(scan_text):
        raw_chunk = cm.group(1)
        low_chunk = raw_chunk.lower()
        if any(kw in low_chunk for kw in _HIGH_SIGNAL_LAZY_CHUNK_KEYWORDS):
            _add_chunk(raw_chunk)

    return {"routes": routes, "chunks": chunks, "manifests": manifests}


def _check_http_scope(
    http_client: AgenticHTTPClient,
    raw_url: str,
    *,
    allow_fragment: bool = False,
) -> tuple[str, str, str]:
    """Validate ``raw_url`` against ``http_client`` strict HTTP scope and custom hooks."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ScopeViolationError("URL is required")
    low = raw.lower()
    if low.startswith(_NON_HTTP_SCHEMES) or low.startswith(("ws://", "wss://")):
        raise ScopeViolationError(f"non-HTTP URL blocked in HTTP context: {raw!r}")
    clean_url, path, query = http_client.resolve_in_scope(raw, allow_websocket=False)
    frag = urlsplit(raw).fragment
    full_url = f"{clean_url}#{frag}" if (allow_fragment and frag.startswith("/")) else clean_url
    _resolve_and_check_scope(http_client, full_url)
    return full_url, path, query


def _is_heavy_media_url(url: str) -> bool:
    path = urlsplit(str(url or "")).path.lower()
    if _extract_path_embedded_params(path):
        return False
    return any(path.endswith(ext) for ext in _HEAVY_MEDIA_EXTS)


def _is_browser_script_asset(req_url: str, req_path: str = "", req: Any = None) -> bool:
    """Return True for read-only static JS/WASM bundle fetches exempt from Stage 0 HTTP budget."""
    raw_url = str(req_url or "").strip()
    if not raw_url:
        return False
    parsed = urlsplit(raw_url)
    path = str(req_path or parsed.path or "").strip()
    if not path or _extract_path_embedded_params(path):
        return False
    low_path = path.lower()
    if _API_PATH_RE.search(low_path):
        return False

    res_type = str(getattr(req, "resource_type", "") or "").strip().lower()
    if res_type == "document":
        return False

    has_script_ext = low_path.endswith(_SCRIPT_ASSET_EXTS)
    has_bundle_path = (
        any(marker in low_path for marker in _SCRIPT_BUNDLE_PATH_MARKERS)
        or is_non_endpoint_source_path(low_path)
    )
    if res_type == "script":
        return bool(has_script_ext or has_bundle_path)
    if has_bundle_path and has_script_ext:
        return True
    if has_script_ext and (not res_type or res_type == "other" or not parsed.query):
        return True
    return False


def _normalized_origin_parts(raw_url: str) -> tuple[str, str, int, str] | None:
    """Parse an explicit http(s) URL into ``(scheme, host, port, formatted_origin)`` or None."""
    raw = str(raw_url or "").strip()
    if not raw or raw.startswith("//") or any(ord(ch) < 32 or ch.isspace() for ch in raw):
        return None
    try:
        parsed = urlsplit(raw)
        port_val = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None
    if port_val is not None and port_val <= 0:
        return None
    default_port = 443 if scheme == "https" else 80
    eff_port = port_val if port_val is not None else default_port
    host_netloc = f"[{host}]" if ":" in host else host
    formatted = f"{scheme}://{host_netloc}" if eff_port == default_port else f"{scheme}://{host_netloc}:{eff_port}"
    return scheme, host, eff_port, formatted


def _registrable_domain(host: str) -> str:
    """Return a best-effort registrable domain suffix without network/PSL dependencies."""
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean or ":" in clean:
        return clean
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        pass
    labels = [lbl for lbl in clean.split(".") if lbl]
    if len(labels) <= 2:
        return clean
    if len(labels[-1]) == 2 and labels[-2] in _MULTI_LABEL_CC_SLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_matches_domain_set(host: str, domains: frozenset[str]) -> bool:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean:
        return False
    return any(clean == dom or clean.endswith("." + dom) for dom in domains)


def _is_tracker_or_telemetry_host(host: str) -> bool:
    """Return True if ``host`` belongs to a known third-party tracker, ad, analytics, or CAPTCHA vendor."""
    return _host_matches_domain_set(host, _THIRD_PARTY_TRACKER_DOMAINS)


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean:
        return None
    try:
        ip = ipaddress.ip_address(clean)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        pass
    # Catch decimal, hex, or octal IPv4 forms (e.g. 2130706433, 0x7f000001, 0177.0.0.1).
    labels = clean.split(".")
    if len(labels) <= 4 and all(
        lbl.isdigit() or (lbl.startswith("0x") and len(lbl) > 2)
        for lbl in labels
        if lbl
    ) and any(labels):
        try:
            packed = socket.inet_aton(clean)
            return ipaddress.IPv4Address(packed)
        except OSError:
            pass
    return None


def _is_link_local_metadata_host(host: str) -> bool:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean:
        return True
    if clean in {"metadata", "metadata.google.internal"} or clean.endswith(".metadata.internal"):
        return True
    ip = _parse_ip_literal(clean)
    if ip is not None:
        return bool(ip.is_link_local or ip.is_unspecified)
    return False


def _is_non_public_or_internal_host(host: str) -> bool:
    """Return True for loopback, private, link-local, CGNAT, reserved, or internal hostnames."""
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean or "%" in clean:
        return True
    ip = _parse_ip_literal(clean)
    if ip is not None:
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
            or not ip.is_global
        ):
            return True
        if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return True
        return False
    if (
        clean == "localhost"
        or clean == "ip6-localhost"
        or clean.endswith((".localhost", ".local", ".internal", ".localdomain", ".home.arpa"))
        or "." not in clean
    ):
        return True
    return False


def _is_allowed_cdn_script_url(req_url: str, base_url: str, req: Any = None) -> bool:
    """Return True strictly for safe, read-only, non-tracker cross-origin CDN JS bundle fetches."""
    req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
    if req_method != "GET":
        return False

    origin_parts = _normalized_origin_parts(req_url)
    if origin_parts is None:
        return False
    req_scheme, req_host, req_port, _req_origin = origin_parts

    base_parts = _normalized_origin_parts(base_url)
    if base_parts is not None:
        base_scheme, base_host, base_port, _base_origin = base_parts
        if (req_scheme, req_host, req_port) == (base_scheme, base_host, base_port):
            return False

    if _is_link_local_metadata_host(req_host):
        return False
    if not is_loopback_or_private_base_url(base_url) and _is_non_public_or_internal_host(req_host):
        return False
    if _is_tracker_or_telemetry_host(req_host):
        return False

    parsed = urlsplit(str(req_url or "").strip())
    path = parsed.path or "/"
    low_path = path.lower()
    if (
        _extract_path_embedded_params(path)
        or _is_heavy_media_url(req_url)
        or is_destructive_lifecycle_route(path)
        or is_logout_route(path)
    ):
        return False

    res_type = str(getattr(req, "resource_type", "") or "").strip().lower()
    if res_type in {"document", "xhr", "fetch", "websocket", "eventsource", "stylesheet", "image", "media", "font"}:
        return False

    if _is_browser_script_asset(req_url, path, req):
        return True
    if res_type == "script":
        return True
    if low_path.endswith((".js", ".mjs")) and not _API_PATH_RE.search(low_path):
        if not res_type or res_type == "other" or not parsed.query:
            return True
    return False


def _classify_seo_route_pattern(
    path: str,
    *,
    method: str = "GET",
    params: Sequence[str] = (),
    is_form: bool = False,
    has_body_template: bool = False,
    has_multipart_schema: bool = False,
) -> str:
    """Return an SEO catalog route pattern class if ``path`` is repetitive storefront/CMS SEO noise."""
    if str(method or "GET").strip().upper() != "GET":
        return ""
    if is_form or has_body_template or has_multipart_schema:
        return ""
    if any(str(p).startswith("path:") for p in params):
        return ""
    raw_path = urlsplit(str(path or "")).path or "/"
    low_path = raw_path.lower()
    if _API_PATH_RE.search(low_path):
        return ""
    segments = [seg for seg in raw_path.split("/") if seg]
    if not segments:
        return ""
    for seg in segments:
        if seg.lower() in _NON_SEO_FUNCTIONAL_SEGMENTS:
            return ""
    for seg in segments:
        if _SEO_CATEGORY_K_RE.fullmatch(seg):
            return "seo_category_k"
        if _SEO_PRODUCT_P_RE.fullmatch(seg):
            return "seo_product_p"
        if _SEO_CATALOG_C_RE.fullmatch(seg):
            return "seo_catalog_c"
    for seg in segments:
        if seg.count("-") >= 4 and not _SEO_UUID_SEG_RE.fullmatch(seg) and not is_id_segment(seg):
            parts = [p for p in seg.split("-") if p]
            if len(parts) >= 5 and sum(1 for p in parts if any(ch.isalpha() for ch in p)) >= 4:
                if not any(p.lower() in _NON_SEO_SLUG_TOKENS for p in parts):
                    return "seo_long_slug"
    return ""


def _is_stage0_noise_path(norm_p: str, *, origin_url: str = "") -> bool:
    """Return True for framework virtual route groups, /$defs/*, bundler chunks, port-in-path, or code/base64 path artifacts."""
    raw = str(norm_p or "").strip()
    if not raw:
        return False
    if is_non_endpoint_source_path(raw) or is_port_in_path_artifact(raw, origin_url=origin_url):
        return True
    low = raw.lower()
    if any(marker in low for marker in _STAGE0_BUNDLER_NOISE_MARKERS):
        return True
    segments = [seg for seg in low.split("/") if seg]
    if any(seg == "$defs" for seg in segments):
        return True
    return any(_ROUTE_GROUP_SEG_RE.fullmatch(seg) for seg in segments)


def should_skip_stage0_form_submit(action_url: str, page_url: str) -> bool:
    """Return True if submitting a Stage 0 form would mutate a virgin-state-sensitive path."""
    raw_action = str(action_url or "").strip()
    raw_page = str(page_url or "").strip()
    if not raw_action or raw_action.startswith("#"):
        target = raw_page
    elif raw_page:
        target = urljoin(raw_page, raw_action)
    else:
        target = raw_action
    return is_virgin_state_sensitive_path(target)


def _sanitize_param_name(raw: Any) -> str:
    name = str(raw or "").strip()
    if not name or not _SAFE_PARAM_NAME_RE.fullmatch(name):
        return ""
    return name


def _normalize_volatile_text(text: str) -> str:
    """Strip volatile UUIDs, hex tokens, timestamps, and numbers for DOM state hashing."""
    s = str(text or "").strip().lower()
    if not s:
        return ""
    s = _VOLATILE_UUID_RE.sub("{uuid}", s)
    s = _VOLATILE_TS_RE.sub("{ts}", s)
    s = _VOLATILE_HEX_RE.sub("{hex}", s)
    s = _VOLATILE_NUM_RE.sub("#", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:48]


def _normalize_hash_route(raw_hash: str) -> str:
    frag = str(raw_hash or "").strip()
    if not frag.startswith("#/"):
        return ""
    inner = frag[1:]
    inner_path = inner.split("?", 1)[0]
    try:
        norm = normalize_path(inner_path)
    except ValueError:
        return ""
    return f"#{route_template_of(norm)}"


def _compute_dom_state_hash(dom_data: dict[str, Any]) -> str:
    """Compute a deterministic structural SHA-256 hash of a rendered DOM state."""
    tokens: list[str] = []
    raw_pathname = str(dom_data.get("pathname") or "/")
    try:
        norm_p = normalize_path(raw_pathname)
    except ValueError:
        norm_p = "/"
    tokens.append(f"path:{route_template_of(norm_p)}")

    norm_hash = _normalize_hash_route(str(dom_data.get("hash") or ""))
    if norm_hash:
        tokens.append(f"hash:{norm_hash}")

    tokens.append(f"dialogs:{int(dom_data.get('dialog_count') or 0)}")

    for h in (dom_data.get("headings") or [])[:24]:
        if not isinstance(h, dict):
            continue
        htag = str(h.get("tag") or "h").lower()[:8]
        htxt = _normalize_volatile_text(str(h.get("text") or ""))
        if htxt:
            tokens.append(f"hd:{htag}:{htxt}:{len(htxt) // 8}")

    for f in (dom_data.get("forms") or [])[:20]:
        if not isinstance(f, dict) or not f.get("visible"):
            continue
        fm = str(f.get("method") or "GET").upper()
        fa = str(f.get("action") or "").split("?", 1)[0]
        fa_tmpl = route_template_of(fa) if fa.startswith("/") else _normalize_volatile_text(fa)
        ffields = sorted(
            f"{str(fld.get('name') or '').lower()}:{str(fld.get('type') or '').lower()}"
            for fld in (f.get("fields") or [])
            if isinstance(fld, dict)
        )
        tokens.append(f"form:{fm}:{fa_tmpl}:{','.join(ffields[:16])}")

    for finp in (dom_data.get("standalone_files") or [])[:12]:
        if not isinstance(finp, dict):
            continue
        fname = str(finp.get("name") or "").lower()[:32]
        facc = str(finp.get("accept") or "").lower()[:32]
        tokens.append(f"file:{fname}:{facc}")

    for c in (dom_data.get("controls") or [])[:40]:
        if not isinstance(c, dict):
            continue
        role = str(c.get("role") or c.get("tag") or "btn").lower()
        sel = str(c.get("aria_selected") or "")
        exp = str(c.get("aria_expanded") or "")
        ac = str(c.get("aria_controls") or "").lower()[:32]
        lbl = _normalize_volatile_text(str(c.get("label") or ""))
        tokens.append(f"ctrl:{role}:{sel}:{exp}:{ac}:{lbl}")

    for raw_link in (dom_data.get("visible_links") or [])[:40]:
        l_str = str(raw_link or "").strip()
        if not l_str:
            continue
        if l_str.startswith("#/"):
            h_norm = _normalize_hash_route(l_str)
            if h_norm:
                tokens.append(f"vlink:{h_norm}")
        else:
            parsed_l = urlsplit(l_str)
            try:
                lp = normalize_path(parsed_l.path or "/")
                tokens.append(f"vlink:{route_template_of(lp)}")
            except ValueError:
                pass

    canonical_blob = "\n".join(sorted(set(tokens)))
    return hashlib.sha256(canonical_blob.encode("utf-8")).hexdigest()[:24]


def _extract_json_param_names(obj: Any, *, prefix: str = "", depth: int = 0) -> list[str]:
    """Extract top-level and nested JSON object key names (never values)."""
    if depth > 3 or not isinstance(obj, dict):
        return []
    out: list[str] = []
    seen: set[str] = set()

    def _add(name: str) -> None:
        clean = _sanitize_param_name(name)
        if clean and clean not in seen and len(out) < _MAX_PARAMS_PER_ROUTE:
            seen.add(clean)
            out.append(clean)

    for raw_k, raw_v in list(obj.items())[:24]:
        key = str(raw_k or "").strip()
        if not key:
            continue
        full = f"{prefix}.{key}" if prefix else key
        _add(full)
        if isinstance(raw_v, dict) and depth < 3:
            for sub in _extract_json_param_names(raw_v, prefix=full, depth=depth + 1):
                _add(sub)
        elif isinstance(raw_v, list) and raw_v and isinstance(raw_v[0], dict) and depth < 2:
            for sub in _extract_json_param_names(raw_v[0], prefix=full, depth=depth + 1):
                _add(sub)
    return out


def _parse_multipart_schema(raw_bytes: bytes, content_type: str = "") -> dict[str, list[str]] | None:
    """Parse multipart/form-data Content-Disposition headers in pure Python (names only)."""
    if not raw_bytes:
        return None
    fields: set[str] = set()
    files: set[str] = set()

    def _inspect_cd_header(cd_bytes: bytes) -> None:
        cd_text = cd_bytes.decode("utf-8", errors="replace")
        m_name = _CD_NAME_RE.search(cd_text)
        if not m_name:
            return
        raw_name = (m_name.group(1) or m_name.group(2) or "").strip()
        clean_name = _sanitize_param_name(raw_name)
        if not clean_name:
            return
        if _CD_FILENAME_RE.search(cd_text):
            if len(files) < 16:
                files.add(clean_name)
        else:
            if len(fields) < 24:
                fields.add(clean_name)

    m_boundary = _BOUNDARY_RE.search(content_type or "")
    if m_boundary:
        boundary_str = (m_boundary.group(1) or m_boundary.group(2) or "").strip()
        if boundary_str:
            delimiter = b"--" + boundary_str.encode("latin-1", errors="ignore")
            parts = raw_bytes.split(delimiter)
            for part in parts[1:]:
                if not part or part.startswith(b"--"):
                    continue
                head_slice = part[:4096]
                sep_idx = head_slice.find(b"\r\n\r\n")
                if sep_idx == -1:
                    sep_idx = head_slice.find(b"\n\n")
                header_block = head_slice[:sep_idx] if sep_idx != -1 else head_slice
                for m_cd in _CD_LINE_RE.finditer(header_block):
                    _inspect_cd_header(m_cd.group(1))

    if not fields and not files:
        # Fallback scan over bounded prefix if Content-Type lacked boundary.
        for m_cd in _CD_LINE_RE.finditer(raw_bytes[:65536]):
            _inspect_cd_header(m_cd.group(1))

    if not fields and not files:
        return None
    return {
        "fields": sorted(fields),
        "files": sorted(files),
    }


def _extract_request_body_artifacts(
    content_type: str,
    post_data: str | None,
    post_data_bytes: bytes | None,
) -> tuple[list[str], dict[str, Any] | None, dict[str, list[str]] | None, bool]:
    """Extract ``(params, body_template, multipart_schema, is_form)`` without keeping raw secrets/files."""
    ctype_full = str(content_type or "")
    ctype = ctype_full.split(";", 1)[0].strip().lower()
    raw_bytes = post_data_bytes
    if raw_bytes is None and isinstance(post_data, str) and post_data:
        raw_bytes = post_data.encode("utf-8", errors="replace")

    if "multipart/form-data" in ctype or (
        raw_bytes is not None and b"Content-Disposition:" in raw_bytes[:2048]
    ):
        schema = _parse_multipart_schema(raw_bytes or b"", ctype_full)
        if schema is not None:
            params = list(dict.fromkeys([*schema["fields"], *schema["files"]]))[:_MAX_PARAMS_PER_ROUTE]
            return params, None, schema, True
        if "multipart/form-data" in ctype:
            return [], None, None, True

    text = post_data
    if text is None and raw_bytes is not None:
        text = raw_bytes[:131072].decode("utf-8", errors="replace")
    stripped = (text or "").strip()
    if not stripped:
        return [], None, None, False

    if "json" in ctype or stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict) and parsed:
            params = _extract_json_param_names(parsed)
            sanitized = _sanitize_json_template(parsed)
            body_template: dict[str, Any] | None = None
            if isinstance(sanitized, dict) and sanitized:
                fitted = _fit_body_template_budget(sanitized)
                if fitted:
                    body_template = fitted
            return params, body_template, None, False
        if "json" in ctype:
            return [], None, None, False

    if "x-www-form-urlencoded" in ctype or ("=" in stripped and not stripped.startswith(("<", "{", "["))):
        pairs = parse_qsl(stripped, keep_blank_values=True, max_num_fields=128)
        params = []
        seen: set[str] = set()
        for k, _ in pairs:
            clean_k = _sanitize_param_name(k)
            if clean_k and clean_k not in seen and len(params) < _MAX_PARAMS_PER_ROUTE:
                seen.add(clean_k)
                params.append(clean_k)
        return params, None, None, True

    return [], None, None, False


def _select_crawl_actors(
    http_client: AgenticHTTPClient,
    actors: Sequence[str] | None,
) -> list[str]:
    """Select up to 2 representative actors (1 non-admin + 1 admin/distinct role/tenant), else ['anon']."""
    actor_map = getattr(http_client.actors, "actors", {}) or {}
    if actors is not None:
        chosen: list[str] = []
        for raw_a in actors:
            alias = str(raw_a or "").strip()
            if alias and alias in actor_map and alias not in chosen:
                chosen.append(alias)
        return chosen or ["anon"]

    summaries_fn = getattr(http_client.actors, "summaries", None)
    summaries = summaries_fn() if callable(summaries_fn) else []
    meta_by_alias: dict[str, dict[str, str]] = {}
    for row in summaries or ():
        if isinstance(row, dict) and row.get("alias"):
            alias = str(row["alias"]).strip()
            meta_by_alias[alias] = {
                "alias": alias,
                "role": str(row.get("role") or "member").strip().lower(),
                "tenant": str(row.get("tenant") or "").strip().lower(),
            }

    def _is_authenticated(alias: str) -> bool:
        if alias == "anon":
            return False
        sess = actor_map.get(alias)
        if sess is not None:
            lock = getattr(sess, "_lock", None)
            ctx = lock if lock is not None else nullcontext()
            with ctx:
                if bool(getattr(sess, "authenticated", False)):
                    return True
        cookie_hdr, extra_hdrs = _extract_actor_browser_auth(http_client, alias)
        local_storage = _extract_actor_local_storage(http_client, alias)
        local_storage_by_origin = (
            _extract_actor_local_storage_by_origin(http_client, alias)
            if callable(_extract_actor_local_storage_by_origin)
            else {}
        )
        cookie_records = (
            _extract_actor_cookie_records(
                http_client,
                alias,
                base_url=http_client.base_url,
                fallback_cookie_hdr=cookie_hdr,
            )
            if callable(_extract_actor_cookie_records)
            else []
        )
        return bool(cookie_hdr or extra_hdrs or local_storage or local_storage_by_origin or cookie_records)

    auth_members: list[dict[str, str]] = []
    auth_admins: list[dict[str, str]] = []

    ordered_aliases = list(dict.fromkeys([*meta_by_alias.keys(), *actor_map.keys()]))
    for alias in ordered_aliases:
        if alias == "anon" or not _is_authenticated(alias):
            continue
        sess = actor_map.get(alias)
        info = meta_by_alias.get(alias) or {
            "alias": alias,
            "role": str(getattr(sess, "role", "member") or "member").strip().lower(),
            "tenant": str(getattr(sess, "tenant", "") or "").strip().lower(),
        }
        if info["role"] in _ADMIN_ROLES:
            auth_admins.append(info)
        else:
            auth_members.append(info)

    selected: list[dict[str, str]] = []
    if auth_members:
        selected.append(auth_members[0])
    if auth_admins:
        selected.append(auth_admins[0])

    if len(selected) < 2:
        pool = [*auth_members[1:], *auth_admins[1:]]
        first = selected[0] if selected else None
        for cand in pool:
            if first is None or cand["role"] != first["role"] or (cand["tenant"] and cand["tenant"] != first["tenant"]):
                selected.append(cand)
                break
        if len(selected) < 2 and pool:
            # Prefer distinct tenant/role first, then any second distinct authenticated actor if none matched above.
            for cand in pool:
                if cand["alias"] not in {s["alias"] for s in selected}:
                    if first is None or cand["tenant"] != first["tenant"] or cand["role"] != first["role"]:
                        selected.append(cand)
                        break

    aliases = [s["alias"] for s in selected[:2]]
    return aliases or ["anon"]


def _choose_synthetic_upload(accept: str) -> dict[str, Any]:
    """Build a tiny in-memory synthetic file payload matching an ``accept`` hint."""
    acc = str(accept or "").lower()
    if "image" in acc or ".png" in acc:
        return {
            "name": "qa-sample.png",
            "mimeType": "image/png",
            "buffer": _TINY_PNG_BYTES,
        }
    if "json" in acc or ".json" in acc:
        return {
            "name": "qa-sample.json",
            "mimeType": "application/json",
            "buffer": b'{"sample":true}',
        }
    return {
        "name": "qa-sample.txt",
        "mimeType": "text/plain",
        "buffer": b"kryon stage0 synthetic sample\n",
    }


def _synthetic_input_value(inp_type: str, *, min_val: str = "") -> str:
    """Return a valid benign synthetic value for a form input type."""
    t = str(inp_type or "text").strip().lower()
    if t == "email":
        return "qa-crawl@example.test"
    if t == "url":
        return "https://example.test/sample"
    if t == "date":
        return "2026-01-15"
    if t == "datetime-local":
        return "2026-01-15T10:00"
    if t == "time":
        return "10:00"
    if t in {"number", "range"}:
        if min_val:
            try:
                num = float(min_val)
                if math.isfinite(num):
                    return str(int(num)) if num.is_integer() else str(num)
            except ValueError:
                pass
        return "1"
    if t == "tel":
        return "5550100"
    if t == "color":
        return "#336699"
    return "qa-sample-value"


def _synthesize_schema_value(resolver: Any, raw_schema: Any, *, depth: int = 0) -> Any:
    """Synthesize a compact placeholder JSON value from an OpenAPI schema node."""
    if depth > 4 or not isinstance(raw_schema, dict):
        return "sample"
    node = resolver.schema(raw_schema, depth) if resolver is not None else raw_schema
    if not isinstance(node, dict):
        return "sample"
    if "example" in node:
        return node["example"]
    if "default" in node:
        return node["default"]
    if isinstance(node.get("enum"), list) and node["enum"]:
        return node["enum"][0]

    typ = resolver.type_of(node) if resolver is not None else str(node.get("type") or "")
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
            resolved_prop = resolver.schema(prop_schema, depth + 1) if resolver is not None else prop_schema
            if isinstance(resolved_prop, dict) and resolved_prop.get("readOnly") is True:
                continue
            out[prop_name] = _synthesize_schema_value(resolver, resolved_prop, depth=depth + 1)
        return out
    if typ == "array":
        items = node.get("items")
        if isinstance(items, dict):
            return [_synthesize_schema_value(resolver, items, depth=depth + 1)]
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
        return "qa-crawl@example.test"
    if fmt in {"uri", "url"}:
        return "https://example.test/sample"
    if fmt == "date":
        return "2026-01-15"
    if fmt == "date-time":
        return "2026-01-15T10:00:00Z"
    if fmt == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    return "sample"


def _resolve_openapi_spec_origin_and_prefix(
    spec: dict[str, Any],
    *,
    base_url: str = "",
    spec_url: str = "",
    path_prefix: str = "",
    scope_guard: Any = None,
) -> tuple[str, str]:
    """Resolve OpenAPI 3 ``servers`` / Swagger 2 ``host`` + ``basePath`` into ``(target_origin, effective_prefix)``."""
    base_parts = _normalized_origin_parts(base_url) if base_url else None
    spec_parts = _normalized_origin_parts(spec_url) if spec_url else None

    def _is_origin_allowed(scheme: str, host: str, port: int) -> bool:
        if scope_guard is not None and hasattr(scope_guard, "check_origin"):
            try:
                return bool(scope_guard.check_origin(scheme, host, port))
            except Exception:
                return False
        if base_parts is not None:
            return (scheme, host, port) == base_parts[:3]
        return True

    def _cross_origin_for(parts: tuple[str, str, int, str] | None) -> str:
        if parts is None:
            return ""
        if base_parts is not None and parts[:3] == base_parts[:3]:
            return ""
        return parts[3]

    resolved_origin = ""
    resolved_prefix = ""

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
            if srv_url.lower().startswith(("http://", "https://")):
                srv_parts = _normalized_origin_parts(srv_url)
                if srv_parts is None:
                    continue
                parsed_srv = urlsplit(srv_url)
                srv_path = (parsed_srv.path or "").strip()
                norm_srv_path = ""
                if srv_path and srv_path != "/" and "{" not in srv_path:
                    try:
                        cand_p = normalize_path(srv_path)
                        if cand_p != "/":
                            norm_srv_path = cand_p
                    except ValueError:
                        norm_srv_path = ""
                if _is_origin_allowed(srv_parts[0], srv_parts[1], srv_parts[2]):
                    resolved_origin = _cross_origin_for(srv_parts)
                    resolved_prefix = norm_srv_path
                    break
                if norm_srv_path and not resolved_prefix:
                    resolved_prefix = norm_srv_path
            elif srv_url.startswith("/") and "{" not in srv_url:
                try:
                    cand_p = normalize_path(srv_url)
                    if cand_p != "/":
                        resolved_prefix = cand_p
                        break
                except ValueError:
                    continue

    if not resolved_origin:
        raw_host = str(spec.get("host") or "").strip()
        raw_bp = str(spec.get("basePath") or "").strip()
        bp_prefix = ""
        if raw_bp and raw_bp != "/" and "{" not in raw_bp:
            try:
                cand_bp = normalize_path(raw_bp if raw_bp.startswith("/") else "/" + raw_bp)
                if cand_bp != "/":
                    bp_prefix = cand_bp
            except ValueError:
                bp_prefix = ""
        if raw_host and "{" not in raw_host:
            raw_schemes = spec.get("schemes")
            schemes = (
                [str(s).strip().lower() for s in raw_schemes if str(s).strip().lower() in {"http", "https"}]
                if isinstance(raw_schemes, list)
                else []
            )
            default_scheme = base_parts[0] if base_parts is not None else (spec_parts[0] if spec_parts is not None else "https")
            scheme_order = list(dict.fromkeys(([default_scheme] if default_scheme in schemes else []) + schemes + [default_scheme]))
            for sch in scheme_order:
                host_parts = _normalized_origin_parts(f"{sch}://{raw_host}")
                if host_parts is not None and _is_origin_allowed(host_parts[0], host_parts[1], host_parts[2]):
                    resolved_origin = _cross_origin_for(host_parts)
                    break
        if bp_prefix and not resolved_prefix:
            resolved_prefix = bp_prefix

    if not resolved_origin and spec_parts is not None and _is_origin_allowed(spec_parts[0], spec_parts[1], spec_parts[2]):
        resolved_origin = _cross_origin_for(spec_parts)

    eff_prefix = path_prefix if path_prefix else resolved_prefix
    return resolved_origin, eff_prefix


def _extract_openapi_templates(
    spec: dict[str, Any],
    *,
    path_prefix: str = "",
    base_url: str = "",
    spec_url: str = "",
    scope_guard: Any = None,
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, list[str]]],
    list[tuple[str, str, list[str]]],
]:
    """Synthesize JSON body templates and multipart schemas from an OpenAPI/Swagger spec."""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return {}, {}, []
    resolver = LocalSchema(spec) if LocalSchema is not None else None
    target_origin, eff_prefix = _resolve_openapi_spec_origin_and_prefix(
        spec,
        base_url=base_url,
        spec_url=spec_url,
        path_prefix=path_prefix,
        scope_guard=scope_guard,
    )
    templates: dict[tuple[str, str], dict[str, Any]] = {}
    multipart_map: dict[tuple[str, str], dict[str, list[str]]] = {}
    ops_meta: list[tuple[str, str, list[str]]] = []

    for raw_path, path_item in spec["paths"].items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        if not raw_path.startswith("/"):
            continue
        eff_path_only = apply_openapi_path_prefix(raw_path, eff_prefix) if eff_prefix else raw_path
        eff_path = f"{target_origin}{eff_path_only}" if target_origin else eff_path_only
        for method_low in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = path_item.get(method_low)
            if not isinstance(op, dict):
                continue
            method = method_low.upper()
            op_params: list[str] = []
            for p_list in (path_item.get("parameters"), op.get("parameters")):
                if not isinstance(p_list, list):
                    continue
                for raw_p in p_list:
                    p_obj = resolver.resolve(raw_p) if (resolver is not None and isinstance(raw_p, dict)) else raw_p
                    if not isinstance(p_obj, dict):
                        continue
                    pname = _sanitize_param_name(p_obj.get("name"))
                    pin = str(p_obj.get("in") or "query").lower()
                    if pin == "body" and method in _FORM_ALLOWED_WRITE_METHODS and isinstance(p_obj.get("schema"), dict):
                        synth = _synthesize_schema_value(resolver, p_obj["schema"])
                        if isinstance(synth, dict) and synth:
                            san = _sanitize_json_template(synth)
                            if isinstance(san, dict) and san:
                                fitted = _fit_body_template_budget(san)
                                if fitted:
                                    templates[(method, eff_path)] = fitted
                                    op_params.extend(_extract_json_param_names(fitted))
                    elif pname and pin in {"query", "formData"}:
                        op_params.append(pname)

            if method in _FORM_ALLOWED_WRITE_METHODS and isinstance(op.get("requestBody"), dict):
                req_body = resolver.resolve(op["requestBody"]) if resolver is not None else op["requestBody"]
                content = req_body.get("content") if isinstance(req_body, dict) else None
                if isinstance(content, dict):
                    json_media: dict[str, Any] | None = None
                    for ct_key, ct_val in content.items():
                        ct_low = str(ct_key or "").lower()
                        if (ct_low == "application/json" or ct_low.endswith("+json")) and isinstance(ct_val, dict):
                            json_media = ct_val
                            break
                    if json_media is not None and isinstance(json_media.get("schema"), dict):
                        synth_obj: Any = None
                        if isinstance(json_media.get("example"), dict):
                            synth_obj = json_media["example"]
                        else:
                            synth_obj = _synthesize_schema_value(resolver, json_media["schema"])
                        if isinstance(synth_obj, dict) and synth_obj:
                            san = _sanitize_json_template(synth_obj)
                            if isinstance(san, dict) and san:
                                fitted = _fit_body_template_budget(san)
                                if fitted:
                                    templates[(method, eff_path)] = fitted
                                    op_params.extend(_extract_json_param_names(fitted))

                    mp_media = content.get("multipart/form-data")
                    if isinstance(mp_media, dict) and isinstance(mp_media.get("schema"), dict):
                        mp_schema = (
                            resolver.schema(mp_media["schema"])
                            if resolver is not None
                            else mp_media["schema"]
                        )
                        props = mp_schema.get("properties") if isinstance(mp_schema, dict) else None
                        if isinstance(props, dict) and props:
                            mp_fields: list[str] = []
                            mp_files: list[str] = []
                            for pk, pv in list(props.items())[:24]:
                                clean_pk = _sanitize_param_name(pk)
                                if not clean_pk:
                                    continue
                                r_pv = resolver.schema(pv) if (resolver is not None and isinstance(pv, dict)) else pv
                                fmt = str(r_pv.get("format") or "").lower() if isinstance(r_pv, dict) else ""
                                if fmt in {"binary", "byte"}:
                                    mp_files.append(clean_pk)
                                else:
                                    mp_fields.append(clean_pk)
                            if mp_fields or mp_files:
                                multipart_map[(method, eff_path)] = {
                                    "fields": sorted(set(mp_fields)),
                                    "files": sorted(set(mp_files)),
                                }
                                op_params.extend(mp_fields)
                                op_params.extend(mp_files)

            ops_meta.append((method, eff_path, list(dict.fromkeys(op_params))[:_MAX_PARAMS_PER_ROUTE]))
            if len(ops_meta) >= 120:
                return templates, multipart_map, ops_meta

    return templates, multipart_map, ops_meta


def _parse_openapi_spec_document(
    body_text: str,
    *,
    content_type: str = "",
    path: str = "",
) -> dict[str, Any] | None:
    """Parse a bounded JSON or YAML OpenAPI/Swagger document if valid."""
    text = str(body_text or "")
    if not text or len(text) > _MAX_OPENAPI_SPEC_BYTES:
        return None
    stripped = text.lstrip()
    if not stripped or stripped.startswith("<"):
        return None
    parsed: Any = None
    if stripped.startswith("{"):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
    else:
        ctype_low = str(content_type or "").lower()
        path_low = str(path or "").lower()
        looks_yaml = (
            "yaml" in ctype_low
            or "yml" in ctype_low
            or path_low.endswith((".yaml", ".yml"))
            or bool(re.search(r"(?m)^\s*(?:openapi|swagger)\s*:", stripped[:4096]))
        )
        if looks_yaml:
            try:
                import yaml  # type: ignore[import-untyped]

                parsed = yaml.safe_load(text)
            except Exception:
                parsed = None
    if (
        isinstance(parsed, dict)
        and isinstance(parsed.get("paths"), dict)
        and ("openapi" in parsed or "swagger" in parsed)
    ):
        return parsed
    return None


def extract_openapi_header_auth_names(spec: dict[str, Any]) -> list[str]:
    """Extract custom header names from OpenAPI 3 ``securitySchemes`` or Swagger 2 ``securityDefinitions``."""
    if not isinstance(spec, dict):
        return []
    resolver = LocalSchema(spec) if LocalSchema is not None else None
    scheme_maps: list[dict[str, Any]] = []
    components = spec.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        scheme_maps.append(components["securitySchemes"])
    sec_defs = spec.get("securityDefinitions")
    if isinstance(sec_defs, dict):
        scheme_maps.append(sec_defs)

    found: list[str] = []
    seen_low: set[str] = set()
    for scheme_map in scheme_maps:
        for raw_scheme in scheme_map.values():
            if not isinstance(raw_scheme, dict):
                continue
            scheme = resolver.resolve(raw_scheme) if resolver is not None else raw_scheme
            if not isinstance(scheme, dict):
                continue
            scheme_type = str(scheme.get("type") or "").strip().lower()
            scheme_in = str(scheme.get("in") or "").strip().lower()
            if scheme_type != "apikey" or scheme_in != "header":
                continue
            hdr_name = str(scheme.get("name") or "").strip()
            if not hdr_name or not _SAFE_OPENAPI_HEADER_NAME_RE.fullmatch(hdr_name):
                continue
            hdr_low = hdr_name.lower()
            if hdr_low in _STANDARD_NON_AUTH_HEADERS or hdr_low in seen_low:
                continue
            seen_low.add(hdr_low)
            found.append(hdr_name)
    return found


def _register_openapi_auth_headers(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    spec: dict[str, Any],
) -> None:
    """Record and register discovered OpenAPI header auth schemes on ``http_client`` if supported."""
    header_names = extract_openapi_header_auth_names(spec)
    if not header_names:
        return
    reg = getattr(http_client, "register_discovered_auth_header", None)
    for hdr_name in header_names:
        is_new = collector.record_discovered_auth_header(hdr_name)
        if is_new and callable(reg):
            try:
                reg(hdr_name, "")
            except TypeError:
                reg(hdr_name)
            except Exception:
                pass


def _ingest_openapi_spec(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    parsed_spec: dict[str, Any],
    *,
    spec_url: str,
    summary_rec: dict[str, Any] | None = None,
) -> None:
    """Ingest operations, templates, and custom header auth schemes from a parsed OpenAPI/Swagger spec."""
    scope_guard = getattr(http_client, "scope_guard", None)
    in_scope_assets = tuple(getattr(scope_guard, "in_scope_assets", ()) or ())
    out_of_scope_assets = tuple(getattr(scope_guard, "out_of_scope_assets", ()) or ())
    oa_prefix = infer_openapi_mount_prefix(parsed_spec, spec_url)
    target_origin, eff_prefix = _resolve_openapi_spec_origin_and_prefix(
        parsed_spec,
        base_url=http_client.base_url,
        spec_url=spec_url,
        path_prefix=oa_prefix,
        scope_guard=scope_guard,
    )
    spec_origin_base = f"{target_origin}/" if target_origin else http_client.base_url

    if summary_rec is not None:
        try:
            summary = _extract_surface_summary(
                summary_rec,
                http_client.base_url,
                in_scope_assets=in_scope_assets,
                out_of_scope_assets=out_of_scope_assets,
            )
            collector.ingest_surface_summary(
                summary,
                source_url=spec_origin_base,
                openapi_path_prefix=eff_prefix,
            )
        except Exception:
            pass

    oa_templates, oa_multipart, oa_ops = _extract_openapi_templates(
        parsed_spec,
        path_prefix=eff_prefix,
        base_url=http_client.base_url,
        spec_url=spec_url,
        scope_guard=scope_guard,
    )
    for op_method, op_path, op_params in oa_ops:
        collector.record_route(
            method=op_method,
            raw_url=op_path,
            current_url=spec_origin_base,
            params=op_params,
            body_template=oa_templates.get((op_method, op_path)),
            body_template_observed=False,
            multipart_schema=oa_multipart.get((op_method, op_path)),
        )
    _register_openapi_auth_headers(http_client, collector, parsed_spec)


def _status_priority(status: int) -> int:
    if 200 <= status < 300 or status in {401, 403}:
        return 8
    if 300 <= status < 400 or status in {400, 405, 422}:
        return 4
    if status == 0:
        return 0
    if status in {404, 410}:
        return -12
    return -3


def _route_priority_score(
    *,
    method: str,
    path: str,
    params: Sequence[str],
    is_form: bool,
    status: int,
    has_body_template: bool,
    has_multipart_schema: bool,
) -> int:
    """Compute a deterministic security-signal score for route ranking."""
    score = 0
    low = path.lower()
    if method in _MUTATING_METHODS:
        score += 50
    if has_multipart_schema:
        score += 45
    if has_body_template:
        score += 35
    if _API_PATH_RE.search(low):
        score += 30
    if any(str(p).startswith("path:") for p in params):
        score += 25
    elif any(str(p).lower() in _HIGH_SIGNAL_PARAM_NAMES for p in params):
        score += 18
    if params:
        score += 15 + min(len(params), 5)
    if is_form:
        score += 12
    if any(kw in low for kw in _HIGH_SIGNAL_PATH_KEYWORDS):
        score += 10
    segments = [seg for seg in path.split("/") if seg]
    score += min(len(segments), 5) * 3
    if any(is_id_segment(seg) for seg in segments):
        score += 8
    score += _status_priority(status)
    if low in _LOW_SIGNAL_EXACT_PATHS:
        score -= 20
    is_api_or_dynamic = bool(
        method in _MUTATING_METHODS
        or has_multipart_schema
        or has_body_template
        or _API_PATH_RE.search(low)
        or any(str(p).startswith("path:") for p in params)
        or is_form
    )
    if low.endswith((".js", ".mjs", ".cjs")) and not is_api_or_dynamic:
        score -= 60
    if _classify_seo_route_pattern(
        path,
        method=method,
        params=params,
        is_form=is_form,
        has_body_template=has_body_template,
        has_multipart_schema=has_multipart_schema,
    ):
        score -= 25
    return score


def _redact_recursive(obj: Any, secrets: Sequence[str]) -> Any:
    """Recursively scrub actor secrets from all strings inside a JSON-serializable structure."""
    if not secrets:
        return obj
    if isinstance(obj, str):
        return _redact_secrets(obj, secrets)
    if isinstance(obj, dict):
        return {
            _redact_secrets(str(k), secrets): _redact_recursive(v, secrets)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_recursive(item, secrets) for item in obj]
    return obj


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write UTF-8 JSON to ``path``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    tmp_path.write_text(serialized, encoding="utf-8")
    os.replace(tmp_path, path)


def _select_discovery_hints(
    routes: Sequence[dict[str, Any]],
    max_hints: int = _MAX_DISCOVERY_HINTS,
) -> list[str]:
    """Select up to ``max_hints`` diverse GET entry paths."""
    cap = max(0, int(max_hints))
    if cap == 0:
        return []
    get_routes = [
        r for r in routes
        if str(r.get("method") or "").upper() == "GET"
        and not str(r.get("url") or "").lower().endswith((".js", ".mjs", ".cjs"))
        and int(r.get("status") or 0) not in {404, 410}
    ]
    if not get_routes:
        get_routes = [r for r in routes if str(r.get("method") or "").upper() == "GET"]

    def _hint_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
        raw_u = str(item.get("url") or "/")
        p = urlsplit(raw_u).path or "/"
        segs = [s for s in p.split("/") if s]
        has_id = 1 if any(is_id_segment(s) for s in segs) else 0
        is_seo = 1 if _classify_seo_route_pattern(
            p,
            method="GET",
            params=item.get("params") or (),
            is_form=bool(item.get("is_form")),
            has_body_template=bool(item.get("body_template")),
            has_multipart_schema=bool(item.get("multipart_schema")),
        ) else 0
        score = _route_priority_score(
            method="GET",
            path=p,
            params=item.get("params") or (),
            is_form=bool(item.get("is_form")),
            status=int(item.get("status") or 0),
            has_body_template=bool(item.get("body_template")),
            has_multipart_schema=bool(item.get("multipart_schema")),
        )
        return (is_seo, has_id, -score, raw_u)

    ranked = sorted(get_routes, key=_hint_key)
    selected: list[str] = []
    seen_paths: set[str] = set()
    seen_templates: set[str] = set()
    seo_hints_count = 0

    for item in ranked:
        if len(selected) >= cap:
            return selected
        p = str(item.get("url") or "")
        parsed_p = urlsplit(p)
        path_only = parsed_p.path or "/"
        is_seo = bool(_classify_seo_route_pattern(
            path_only,
            method="GET",
            params=item.get("params") or (),
            is_form=bool(item.get("is_form")),
            has_body_template=bool(item.get("body_template")),
            has_multipart_schema=bool(item.get("multipart_schema")),
        ))
        if is_seo and seo_hints_count >= _MAX_SEO_DISCOVERY_HINTS:
            continue
        tmpl_path = route_template_of(path_only)
        tmpl = f"{parsed_p.scheme}://{parsed_p.netloc}{tmpl_path}" if parsed_p.netloc else tmpl_path
        if not p or p in seen_paths or tmpl in seen_templates:
            continue
        seen_paths.add(p)
        seen_templates.add(tmpl)
        if is_seo:
            seo_hints_count += 1
        selected.append(p)

    for item in ranked:
        if len(selected) >= cap:
            break
        p = str(item.get("url") or "")
        path_only = urlsplit(p).path or "/"
        is_seo = bool(_classify_seo_route_pattern(
            path_only,
            method="GET",
            params=item.get("params") or (),
            is_form=bool(item.get("is_form")),
            has_body_template=bool(item.get("body_template")),
            has_multipart_schema=bool(item.get("multipart_schema")),
        ))
        if is_seo and seo_hints_count >= _MAX_SEO_DISCOVERY_HINTS:
            continue
        if not p or p in seen_paths:
            continue
        seen_paths.add(p)
        if is_seo:
            seo_hints_count += 1
        selected.append(p)

    return selected


def _try_reauthenticate_actor(http_client: AgenticHTTPClient, actor: str) -> None:
    """Best-effort re-authentication if an authenticated actor session drops during form crawl."""
    if actor == "anon":
        return
    auth_fn = getattr(http_client, "authenticate_actor", None)
    if not callable(auth_fn):
        return
    param_names: set[str]
    try:
        param_names = set(inspect.signature(auth_fn).parameters)
    except (TypeError, ValueError):
        param_names = set()
    try:
        if "force_login" in param_names:
            auth_fn(actor, force_login=True)
        elif "force" in param_names:
            auth_fn(actor, force=True)
        else:
            auth_fn(actor)
    except Exception:
        pass


class _Stage0Collector:
    """Shared state accumulator across Playwright crawl and Layer 4 passive fusion."""

    def __init__(self, http_client: AgenticHTTPClient) -> None:
        self.http = http_client
        self._allow_canonical_host_aliases = is_loopback_or_private_base_url(http_client.base_url)
        self.internal_canonical_hosts: set[str] = set()
        self.routes: dict[tuple[str, str], _RouteRecord] = {}
        self.ws_endpoints: dict[tuple[str, str], dict[str, str]] = {}
        self.captured_html: dict[str, dict[str, Any]] = {}
        self.captured_js: dict[str, dict[str, Any]] = {}
        self.captured_css: dict[str, dict[str, Any]] = {}
        self.captured_specs: dict[str, tuple[str, dict[str, Any]]] = {}
        self.discovered_spec_urls: list[str] = []
        self.fetched_2xx_paths: set[str] = set()
        self.probed_paths: set[str] = set()
        self.discovered_auth_headers: list[str] = []
        self._seen_auth_headers_low: set[str] = set()
        self.observed_app_headers: dict[str, str] = {}
        self.server_headers: list[str] = []
        self.powered_by_headers: list[str] = []
        self.body_snippets: list[str] = []
        self.script_assets_seen: set[str] = set()
        self.script_assets_requests = 0
        self.cdn_script_assets_seen: set[str] = set()
        self.cdn_script_assets_requests = 0
        self.external_api_hosts: dict[str, _ExternalAPIHostRecord] = {}
        self._seo_buffer_counts: dict[str, int] = {}
        self._lazy_chunks_seen: set[str] = set()
        self._seen_order = 0
        self._lock = threading.Lock()

        # Counters
        self.pages_visited = 0
        self.dom_states_seen = 0
        self.ui_actions_taken = 0
        self.forms_submitted = 0
        self.uploads_triggered = 0
        self.network_requests_captured = 0
        self.js_chunks_parsed = 0
        self.cdn_js_chunks_parsed = 0
        self.source_maps_parsed = 0
        self.lazy_chunks_discovered = 0
        self.passive_probes_sent = 0

    def record_observed_app_headers(
        self,
        raw_headers: dict[str, Any],
        *,
        blocked_names: set[str] | frozenset[str] = frozenset(),
    ) -> None:
        """Record safe non-secret XHR app headers observed during network interception."""
        safe = _sanitize_observed_app_headers(raw_headers, blocked_names=blocked_names)
        if not safe:
            return
        with self._lock:
            existing_low = {k.lower(): k for k in self.observed_app_headers}
            for hk, hv in safe.items():
                low = hk.lower()
                if low in existing_low or low in self._seen_auth_headers_low:
                    continue
                if len(self.observed_app_headers) >= _MAX_OBSERVED_APP_HEADERS:
                    break
                self.observed_app_headers[hk] = hv
                existing_low[low] = hk

    def record_lazy_chunks(self, chunk_refs: Sequence[str]) -> int:
        """Track unique discovered lazy SPA chunk/manifest references."""
        added = 0
        with self._lock:
            for raw_c in chunk_refs:
                c = str(raw_c or "").strip()
                if not c or c in self._lazy_chunks_seen:
                    continue
                if len(self._lazy_chunks_seen) >= 256:
                    break
                self._lazy_chunks_seen.add(c)
                added += 1
            self.lazy_chunks_discovered = len(self._lazy_chunks_seen)
        return added

    def record_discovered_auth_header(self, header_name: str) -> bool:
        """Record a custom OpenAPI auth header name once (case-insensitive)."""
        clean = str(header_name or "").strip()
        if not clean:
            return False
        low = clean.lower()
        with self._lock:
            if low in self._seen_auth_headers_low:
                return False
            self._seen_auth_headers_low.add(low)
            self.discovered_auth_headers.append(clean)
            return True

    def try_reserve_script_asset(self, clean_url: str) -> bool:
        """Allow up to ``_MAX_STAGE0_SCRIPT_ASSETS`` unique browser script assets per crawl."""
        key = str(clean_url or "").strip()
        if not key:
            return False
        with self._lock:
            if self.script_assets_requests >= _MAX_STAGE0_SCRIPT_ASSETS * 3:
                return False
            if key not in self.script_assets_seen:
                if len(self.script_assets_seen) >= _MAX_STAGE0_SCRIPT_ASSETS:
                    return False
                self.script_assets_seen.add(key)
            self.script_assets_requests += 1
            return True

    def try_reserve_cdn_script_asset(self, clean_url: str) -> bool:
        """Allow up to ``_MAX_STAGE0_CDN_SCRIPT_ASSETS`` unique cross-origin CDN JS bundles."""
        key = str(clean_url or "").strip()
        if not key:
            return False
        with self._lock:
            if self.cdn_script_assets_requests >= _MAX_STAGE0_CDN_SCRIPT_ASSETS * 3:
                return False
            if self.script_assets_requests >= _MAX_STAGE0_SCRIPT_ASSETS * 3:
                return False
            if key not in self.cdn_script_assets_seen and len(self.cdn_script_assets_seen) >= _MAX_STAGE0_CDN_SCRIPT_ASSETS:
                return False
            if key not in self.script_assets_seen and len(self.script_assets_seen) >= _MAX_STAGE0_SCRIPT_ASSETS:
                return False
            self.cdn_script_assets_seen.add(key)
            self.script_assets_seen.add(key)
            self.cdn_script_assets_requests += 1
            self.script_assets_requests += 1
            return True

    def is_reserved_cdn_script(self, clean_url: str) -> bool:
        key = str(clean_url or "").strip()
        if not key:
            return False
        with self._lock:
            return key in self.cdn_script_assets_seen

    def record_external_api_observation(self, raw_url: str, method: str = "GET") -> bool:
        """Record a non-tracker cross-origin API/sibling host and bounded sample path."""
        parts = _normalized_origin_parts(raw_url)
        if parts is None:
            return False
        scheme, host, port, origin = parts
        base_parts = _normalized_origin_parts(self.http.base_url)
        if base_parts is not None and (scheme, host, port) == (base_parts[0], base_parts[1], base_parts[2]):
            return False
        if _is_link_local_metadata_host(host):
            return False
        if not is_loopback_or_private_base_url(self.http.base_url) and _is_non_public_or_internal_host(host):
            return False
        if _is_tracker_or_telemetry_host(host):
            return False

        parsed = urlsplit(str(raw_url or "").strip())
        try:
            norm_p = normalize_path(parsed.path or "/")
        except ValueError:
            norm_p = "/"
        low_p = norm_p.lower()
        is_static_file = (
            _is_heavy_media_url(raw_url)
            or is_static_asset_url(norm_p)
            or low_p.endswith((".js", ".mjs", ".cjs", ".css", ".map", ".svg"))
        )
        if is_static_file and norm_p != "/" and not _API_PATH_RE.search(low_p):
            return False

        norm_method = str(method or "GET").strip().upper()
        if norm_method not in _VALID_HTTP_METHODS:
            norm_method = "GET"

        base_host = base_parts[1] if base_parts is not None else ""
        base_reg = _registrable_domain(base_host)
        same_reg = bool(base_reg and _registrable_domain(host) == base_reg and not is_loopback_or_private_base_url(self.http.base_url))

        with self._lock:
            entry = self.external_api_hosts.get(origin)
            if entry is None:
                if len(self.external_api_hosts) >= _MAX_DISCOVERED_API_HOSTS:
                    return False
                entry = _ExternalAPIHostRecord(
                    origin=origin,
                    host=host,
                    same_registrable_domain=same_reg,
                )
                self.external_api_hosts[origin] = entry
            entry.methods.add(norm_method)
            entry.observation_count += 1
            if norm_p != "/" and "/" in entry.sample_paths:
                entry.sample_paths.remove("/")
            if norm_p not in entry.sample_paths and len(entry.sample_paths) < _MAX_API_HOST_SAMPLE_PATHS:
                if norm_p != "/" or not entry.sample_paths:
                    entry.sample_paths.append(norm_p)
        return True

    def export_discovered_api_hosts(self) -> list[dict[str, Any]]:
        """Return a deterministic sorted summary of observed external/sibling API origins."""
        with self._lock:
            snapshot = [
                _ExternalAPIHostRecord(
                    origin=item.origin,
                    host=item.host,
                    same_registrable_domain=item.same_registrable_domain,
                    methods=set(item.methods),
                    sample_paths=list(item.sample_paths),
                    observation_count=item.observation_count,
                )
                for item in self.external_api_hosts.values()
            ]
        snapshot.sort(
            key=lambda item: (
                0 if item.same_registrable_domain else 1,
                0 if any(p != "/" for p in item.sample_paths) else 1,
                -item.observation_count,
                item.origin,
            )
        )
        return [
            {
                "origin": item.origin,
                "host": item.host,
                "same_registrable_domain": item.same_registrable_domain,
                "methods": sorted(item.methods),
                "sample_paths": item.sample_paths,
                "observation_count": item.observation_count,
            }
            for item in snapshot
        ]

    def record_ws_endpoint(self, raw_ws_url: str) -> bool:
        """Validate and record a same-origin WebSocket URL; reject off-origin or excluded."""
        raw = str(raw_ws_url or "").strip()
        if not raw or not raw.lower().startswith(("ws://", "wss://")):
            return False
        try:
            clean_ws, ws_path, _ws_query = self.http.resolve_in_scope(raw, allow_websocket=True)
        except ScopeViolationError:
            return False
        try:
            norm_ws_path = normalize_path(ws_path)
        except ValueError:
            return False
        key = (clean_ws, norm_ws_path)
        with self._lock:
            if key not in self.ws_endpoints and len(self.ws_endpoints) < 40:
                self.ws_endpoints[key] = {"url": clean_ws, "path": norm_ws_path}
        return True

    def register_canonical_hosts(self, hosts: Iterable[str]) -> None:
        """Record validated single-label internal canonical host aliases (loopback/private targets only)."""
        if not self._allow_canonical_host_aliases:
            return
        valid = {
            h.strip().lower()
            for h in hosts
            if isinstance(h, str) and is_single_label_internal_host(h)
        }
        if not valid:
            return
        with self._lock:
            self.internal_canonical_hosts.update(valid)

    def canonical_hosts_snapshot(self) -> set[str]:
        if not self._allow_canonical_host_aliases:
            return set()
        with self._lock:
            return set(self.internal_canonical_hosts)

    def rewrite_canonical_url(self, raw_url: str) -> str:
        """Rewrite a validated internal single-label canonical host URL to ``self.http.base_url``."""
        if not self._allow_canonical_host_aliases:
            return raw_url
        aliases = self.canonical_hosts_snapshot()
        if not aliases:
            return raw_url
        return rewrite_internal_canonical_url(
            raw_url,
            base_url=self.http.base_url,
            canonical_hosts=aliases,
        )

    def record_route(
        self,
        *,
        method: str,
        raw_url: str,
        current_url: str = "",
        params: Sequence[str] = (),
        status: int = 0,
        is_form: bool = False,
        body_template: dict[str, Any] | None = None,
        body_template_observed: bool = False,
        multipart_schema: dict[str, list[str]] | None = None,
    ) -> bool:
        """Scope-check, normalize, filter, and merge a discovered route into the table."""
        norm_method = str(method or "GET").strip().upper()
        if norm_method not in _VALID_HTTP_METHODS:
            norm_method = "GET"
        raw = str(raw_url or "").strip()
        if raw and self._allow_canonical_host_aliases:
            raw = self.rewrite_canonical_url(raw)
        if not raw or raw.startswith(("#", "//")) or raw.lower().startswith(_NON_HTTP_SCHEMES):
            return False
        if raw.lower().startswith(("ws://", "wss://")):
            return self.record_ws_endpoint(raw)
        if is_non_endpoint_source_path(raw):
            return False

        base_ref = urljoin(self.http.base_url, current_url) if current_url else self.http.base_url
        raw = normalize_bare_hostport_url(raw, base=base_ref)
        if not raw or is_port_in_path_artifact(raw, origin_url=self.http.base_url):
            return False
        resolved = urljoin(base_ref, raw)
        try:
            _clean_url, raw_path, raw_query = _check_http_scope(self.http, resolved, allow_fragment=False)
        except ScopeViolationError:
            return False
        try:
            norm_p = normalize_path(raw_path or "/")
        except ValueError:
            return False

        clean_origin_parts = _normalized_origin_parts(_clean_url)
        base_origin_parts = _normalized_origin_parts(self.http.base_url)
        is_cross_origin = bool(
            clean_origin_parts is not None
            and base_origin_parts is not None
            and clean_origin_parts[:3] != base_origin_parts[:3]
        )
        route_origin = clean_origin_parts[3] if (is_cross_origin and clean_origin_parts is not None) else ""

        path_params = _extract_path_embedded_params(norm_p)
        if (
            has_double_slash_path(raw_path)
            or (is_static_asset_url(norm_p) and not path_params)
            or is_non_endpoint_source_path(norm_p)
            or _is_stage0_noise_path(norm_p, origin_url=self.http.base_url)
        ):
            return False

        if is_cross_origin:
            self.record_external_api_observation(_clean_url, method=norm_method)

        merged_params: list[str] = []
        if raw_query:
            for qk, _ in parse_qsl(raw_query, keep_blank_values=True, max_num_fields=128):
                clean_k = _sanitize_param_name(qk)
                if clean_k:
                    merged_params.append(clean_k)
        for p in params:
            pname = str(p.get("name") if isinstance(p, dict) else p or "").strip()
            clean_p = _sanitize_param_name(pname)
            if clean_p:
                merged_params.append(clean_p)
        for pp in path_params:
            clean_pp = _sanitize_param_name(pp)
            if clean_pp:
                merged_params.append(clean_pp)

        san_body: dict[str, Any] | None = None
        if isinstance(body_template, dict) and body_template:
            san = _sanitize_json_template(body_template)
            if isinstance(san, dict) and san:
                fitted = _fit_body_template_budget(san)
                if fitted:
                    san_body = fitted

        mp_fields: list[str] = []
        mp_files: list[str] = []
        if isinstance(multipart_schema, dict):
            for f in multipart_schema.get("fields") or ():
                cf = _sanitize_param_name(f)
                if cf:
                    mp_fields.append(cf)
            for fl in multipart_schema.get("files") or ():
                cfl = _sanitize_param_name(fl)
                if cfl:
                    mp_files.append(cfl)
            merged_params.extend(mp_fields)
            merged_params.extend(mp_files)

        route_key_target = f"{route_origin}{norm_p}" if route_origin else norm_p
        key = (norm_method, route_key_target)
        seo_pattern = _classify_seo_route_pattern(
            norm_p,
            method=norm_method,
            params=merged_params,
            is_form=bool(is_form or mp_fields or mp_files),
            has_body_template=san_body is not None,
            has_multipart_schema=bool(mp_fields or mp_files),
        )
        with self._lock:
            rec = self.routes.get(key)
            if rec is None:
                if seo_pattern:
                    buf_cnt = self._seo_buffer_counts.get(seo_pattern, 0)
                    if buf_cnt >= _MAX_SEO_COLLECTOR_BUFFER:
                        return False
                    self._seo_buffer_counts[seo_pattern] = buf_cnt + 1
                self._seen_order += 1
                rec = _RouteRecord(
                    method=norm_method,
                    path=norm_p,
                    origin=route_origin,
                    is_form=bool(is_form or mp_fields or mp_files),
                    best_status=int(status or 0),
                    first_seen=self._seen_order,
                )
                self.routes[key] = rec
            else:
                if is_form or mp_fields or mp_files:
                    rec.is_form = True
                if status and _status_priority(int(status)) > _status_priority(rec.best_status):
                    rec.best_status = int(status)

            for p_name in merged_params:
                if len(rec.params) >= _MAX_PARAMS_PER_ROUTE:
                    break
                rec.params.add(p_name)

            if san_body is not None:
                should_replace = (
                    rec.body_template is None
                    or (body_template_observed and not rec.body_template_observed)
                    or (
                        body_template_observed == rec.body_template_observed
                        and len(san_body) > len(rec.body_template)
                    )
                )
                if should_replace:
                    rec.body_template = san_body
                    rec.body_template_observed = bool(body_template_observed)

            for mf in mp_fields:
                if len(rec.multipart_fields) < 24:
                    rec.multipart_fields.add(mf)
            for mfl in mp_files:
                if len(rec.multipart_files) < 16:
                    rec.multipart_files.add(mfl)

            if 200 <= int(status or 0) < 300 and norm_method == "GET":
                self.fetched_2xx_paths.add(route_key_target)
        return True

    def record_document(
        self,
        *,
        url: str,
        content_type: str,
        body: str,
        headers: dict[str, str],
        is_js: bool,
        is_css: bool = False,
        is_cdn_js: bool = False,
    ) -> None:
        if not body:
            return
        base_parts = _normalized_origin_parts(self.http.base_url)
        doc_parts = _normalized_origin_parts(url)
        cross_origin_doc = bool(
            is_cdn_js
            or (
                doc_parts is not None
                and base_parts is not None
                and doc_parts[:3] != base_parts[:3]
            )
        )
        with self._lock:
            if not cross_origin_doc:
                srv = headers.get("server") or headers.get("Server") or ""
                xpb = headers.get("x-powered-by") or headers.get("X-Powered-By") or ""
                if srv and srv not in self.server_headers and len(self.server_headers) < 8:
                    self.server_headers.append(srv)
                if xpb and xpb not in self.powered_by_headers and len(self.powered_by_headers) < 8:
                    self.powered_by_headers.append(xpb)
                if not is_js and not is_css and len(self.body_snippets) < 4:
                    self.body_snippets.append(body[:8192])

            parsed = urlsplit(url)
            try:
                norm_p = normalize_path(parsed.path or "/")
            except ValueError:
                norm_p = parsed.path or "/"

            entry = {
                "url": url,
                "content_type": content_type,
                "body": body,
                "headers": dict(headers),
                "is_cdn": cross_origin_doc,
            }
            if is_css:
                css_key = f"{doc_parts[3]}{norm_p}" if (cross_origin_doc and doc_parts is not None) else norm_p
                store, store_key, cap = self.captured_css, css_key, _MAX_CSS_DOCS
            elif is_js:
                js_key = f"{doc_parts[3]}{norm_p}" if (cross_origin_doc and doc_parts is not None) else norm_p
                store, store_key, cap = self.captured_js, js_key, _MAX_JS_CHUNKS
            else:
                doc_path_q = f"{norm_p}?{parsed.query}" if parsed.query else norm_p
                doc_key = f"{doc_parts[3]}{doc_path_q}" if (cross_origin_doc and doc_parts is not None) else doc_path_q
                store, store_key, cap = self.captured_html, doc_key, _MAX_HTML_DOCS
            if store_key not in store and len(store) < cap:
                store[store_key] = entry

    def ingest_surface_summary(
        self,
        summary: dict[str, Any],
        *,
        source_url: str,
        openapi_path_prefix: str = "",
    ) -> None:
        """Ingest routes extracted by ``agentic_preview._extract_surface_summary``."""
        if not isinstance(summary, dict):
            return
        for form_item in summary.get("forms") or ():
            if not isinstance(form_item, dict):
                continue
            self.record_route(
                method=str(form_item.get("method") or "GET"),
                raw_url=str(form_item.get("url") or ""),
                current_url=source_url,
                params=form_item.get("params") or (),
                is_form=True,
            )
        for item in [
            *(summary.get("links") or ()),
            *(summary.get("js_calls") or ()),
            *(summary.get("spa_routes") or ()),
        ]:
            if not isinstance(item, dict):
                continue
            self.record_route(
                method=str(item.get("method") or "GET"),
                raw_url=str(item.get("url") or ""),
                current_url=source_url,
                params=item.get("params") or (),
            )
        for op in summary.get("openapi_operations") or ():
            if not isinstance(op, dict):
                continue
            pnames: list[str] = []
            for p in op.get("params") or ():
                if isinstance(p, dict) and p.get("name"):
                    pnames.append(str(p["name"]))
                elif isinstance(p, str):
                    pnames.append(p)
            pnames.extend(str(f) for f in (op.get("body_fields") or ()) if f)
            op_full_url = str(op.get("url") or "").strip()
            op_rel_path = str(op.get("path") or "").strip()
            raw_op_url = op_full_url if op_full_url.lower().startswith(("http://", "https://")) else (op_rel_path or op_full_url)
            if openapi_path_prefix and raw_op_url:
                op_parsed = urlsplit(raw_op_url)
                prefixed_path = apply_openapi_path_prefix(op_parsed.path or raw_op_url, openapi_path_prefix)
                if op_parsed.scheme in {"http", "https"} and op_parsed.netloc:
                    raw_op_url = f"{op_parsed.scheme.lower()}://{op_parsed.netloc}{prefixed_path}"
                else:
                    raw_op_url = prefixed_path
            self.record_route(
                method=str(op.get("method") or "GET"),
                raw_url=raw_op_url,
                current_url=source_url or self.http.base_url,
                params=pnames,
            )
        for pop in summary.get("postman_ops") or ():
            if not isinstance(pop, dict):
                continue
            self.record_route(
                method=str(pop.get("method") or "GET"),
                raw_url=str(pop.get("url") or ""),
                current_url=self.http.base_url,
                params=pop.get("body_keys") or (),
            )
        cl = summary.get("client_logic")
        if isinstance(cl, dict):
            for ep in cl.get("endpoints") or ():
                if not isinstance(ep, dict):
                    continue
                ep_params = [
                    *(ep.get("query_params") or ()),
                    *(ep.get("body_fields") or ()),
                ]
                self.record_route(
                    method=str(ep.get("method") or "GET"),
                    raw_url=str(ep.get("path") or ep.get("url") or ""),
                    current_url=source_url,
                    params=ep_params,
                )
        for spec_u in summary.get("spec_urls") or ():
            if not isinstance(spec_u, str) or not spec_u.strip():
                continue
            try:
                clean_sp_u, sp_path, _q = _check_http_scope(self.http, spec_u, allow_fragment=False)
                norm_sp = normalize_path(sp_path)
            except (ScopeViolationError, ValueError):
                continue
            if not _is_skipped_surface_url(norm_sp):
                spec_key = _scoped_storage_key(clean_sp_u, self.http.base_url)
                with self._lock:
                    if spec_key not in self.discovered_spec_urls and len(self.discovered_spec_urls) < 12:
                        self.discovered_spec_urls.append(spec_key)


def _detect_canonical_hosts_from_dom(
    dom_data: dict[str, Any],
    *,
    base_url: str,
) -> set[str]:
    """Detect single-label internal canonical hostnames from a Playwright DOM snapshot."""
    if not is_loopback_or_private_base_url(base_url) or not isinstance(dom_data, dict):
        return set()
    base_host = (urlsplit(base_url).hostname or "").strip().lower()
    detected: set[str] = set()

    for chref in dom_data.get("canonical_links") or ():
        cand = _extract_single_label_url_host(str(chref or ""))
        if cand and cand != base_host:
            detected.add(cand)

    for b_key in ("base_href", "base_uri"):
        cand = _extract_single_label_url_host(str(dom_data.get(b_key) or ""))
        if cand and cand != base_host:
            detected.add(cand)

    counts: dict[str, int] = {}
    for link_raw in dom_data.get("links") or ():
        cand = _extract_single_label_url_host(str(link_raw or ""))
        if cand and cand != base_host:
            counts[cand] = counts.get(cand, 0) + 1
    for form_item in dom_data.get("forms") or ():
        if not isinstance(form_item, dict):
            continue
        cand = _extract_single_label_url_host(str(form_item.get("action") or ""))
        if cand and cand != base_host:
            counts[cand] = counts.get(cand, 0) + 1
    if counts:
        max_count = max(counts.values())
        if max_count >= 3:
            for host, cnt in counts.items():
                if cnt == max_count:
                    detected.add(host)

    return detected


def _fill_and_submit_form(
    page: Any,
    form_info: dict[str, Any],
    *,
    timeout_ms: int,
    rewritten_action: str = "",
) -> tuple[bool, bool]:
    """Fill a benign visible form with synthetic data and click its safe submit trigger.

    Returns ``(submitted, uploaded_file)``.
    """
    form_idx = int(form_info.get("form_index", -1))
    if form_idx < 0:
        return False, False
    try:
        form_handle = page.evaluate_handle(
            "idx => (window.__kryonStage0 && window.__kryonStage0.forms && window.__kryonStage0.forms[idx]) || null",
            form_idx,
        ).as_element()
    except Exception:
        return False, False
    if form_handle is None:
        return False, False
    if rewritten_action:
        try:
            form_handle.evaluate(
                "(el, act) => { if (el && typeof el.setAttribute === 'function') el.setAttribute('action', act); }",
                rewritten_action,
            )
        except Exception:
            pass

    attached_file = False
    seen_radio_groups: set[str] = set()
    try:
        inputs = form_handle.query_selector_all("input, textarea, select")
    except Exception:
        inputs = []

    for inp in inputs:
        try:
            meta = inp.evaluate(
                """el => {
                  const tag = String(el.tagName || '').toLowerCase();
                  const typ = tag === 'input' ? String(el.getAttribute('type') || 'text').toLowerCase() : tag;
                  const style = window.getComputedStyle ? window.getComputedStyle(el) : null;
                  const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : {width: 0, height: 0};
                  const vis = !!(rect.width > 0 && rect.height > 0 && (!style || (style.display !== 'none' && style.visibility !== 'hidden')));
                  let selectVal = null;
                  let selectIdx = -1;
                  if (tag === 'select' && el.options) {
                    for (let i = 0; i < el.options.length; i++) {
                      const opt = el.options[i];
                      if (opt.disabled) continue;
                      if (selectIdx === -1) selectIdx = i;
                      if (String(opt.value || '').trim() !== '') {
                        selectVal = String(opt.value);
                        selectIdx = i;
                        break;
                      }
                    }
                  }
                  return {
                    tag,
                    typ,
                    name: String(el.getAttribute('name') || ''),
                    id: String(el.id || ''),
                    aria: String(el.getAttribute('aria-label') || ''),
                    accept: String(el.getAttribute('accept') || ''),
                    min: String(el.getAttribute('min') || ''),
                    disabled: !!el.disabled,
                    readonly: !!el.readOnly,
                    vis,
                    selectVal,
                    selectIdx,
                  };
                }"""
            )
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        if meta.get("disabled") or meta.get("readonly"):
            continue
        tag = str(meta.get("tag") or "").lower()
        typ = str(meta.get("typ") or "text").lower()
        if typ in {"hidden", "submit", "button", "reset", "image"}:
            continue

        if typ == "file":
            try:
                inp.set_input_files(_choose_synthetic_upload(str(meta.get("accept") or "")))
                attached_file = True
            except Exception:
                pass
            continue

        if not meta.get("vis"):
            continue

        hay = f"{meta.get('name', '')} {meta.get('id', '')} {meta.get('aria', '')}"
        if typ == "checkbox":
            if not _DESTRUCTIVE_RE.search(hay):
                try:
                    inp.check(timeout=1500)
                except Exception:
                    try:
                        inp.evaluate("el => { if (!el.checked) el.click(); }")
                    except Exception:
                        pass
            continue

        if typ == "radio":
            group = str(meta.get("name") or meta.get("id") or "__radio__")
            if group not in seen_radio_groups:
                seen_radio_groups.add(group)
                try:
                    inp.check(timeout=1500)
                except Exception:
                    try:
                        inp.evaluate("el => { if (!el.checked) el.click(); }")
                    except Exception:
                        pass
            continue

        if tag == "select":
            sel_val = meta.get("selectVal")
            sel_idx = int(meta.get("selectIdx", -1))
            try:
                if sel_val is not None:
                    inp.select_option(value=str(sel_val), timeout=1500)
                elif sel_idx >= 0:
                    inp.select_option(index=sel_idx, timeout=1500)
            except Exception:
                pass
            continue

        val = _synthetic_input_value(typ, min_val=str(meta.get("min") or ""))
        try:
            inp.fill(val, timeout=1500)
        except Exception:
            try:
                inp.evaluate(
                    """(el, v) => {
                      el.value = v;
                      el.dispatchEvent(new Event('input', {bubbles: true}));
                      el.dispatchEvent(new Event('change', {bubbles: true}));
                    }""",
                    val,
                )
            except Exception:
                pass

    # Locate a safe submit trigger inside the form.
    try:
        submit_els = form_handle.query_selector_all(
            'button[type="submit"], input[type="submit"], button:not([type])'
        )
    except Exception:
        submit_els = []

    chosen_submit: Any = None
    saw_any_submit = False
    for btn in submit_els:
        try:
            bmeta = btn.evaluate(
                """el => {
                  const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : {width: 0, height: 0};
                  return {
                    disabled: !!el.disabled,
                    vis: !!(rect.width > 0 && rect.height > 0),
                    hay: [
                      el.textContent || '',
                      el.getAttribute('value') || '',
                      el.id || '',
                      el.getAttribute('name') || '',
                      el.getAttribute('aria-label') || '',
                    ].join(' '),
                  };
                }"""
            )
        except Exception:
            continue
        if not isinstance(bmeta, dict) or bmeta.get("disabled") or not bmeta.get("vis"):
            continue
        saw_any_submit = True
        if _DESTRUCTIVE_RE.search(str(bmeta.get("hay") or "")):
            continue
        chosen_submit = btn
        break

    if saw_any_submit and chosen_submit is None:
        # Every visible submit button in this form looked destructive; abort submission.
        return False, False

    click_timeout = min(3000, max(1000, int(timeout_ms)))
    if chosen_submit is not None:
        try:
            chosen_submit.click(timeout=click_timeout)
            return True, attached_file
        except Exception:
            try:
                chosen_submit.evaluate("el => el.click()")
                return True, attached_file
            except Exception:
                return False, False

    try:
        form_handle.evaluate(
            """f => {
              if (typeof f.requestSubmit === 'function') {
                f.requestSubmit();
              } else {
                f.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
              }
            }"""
        )
        return True, attached_file
    except Exception:
        return False, False


def _trigger_standalone_file_input(page: Any, file_info: dict[str, Any]) -> bool:
    """Attach a synthetic file to a standalone ``input[type=file]`` outside any ``<form>``."""
    fidx = int(file_info.get("file_index", -1))
    if fidx < 0:
        return False
    try:
        elem = page.evaluate_handle(
            "idx => (window.__kryonStage0 && window.__kryonStage0.standaloneFiles && window.__kryonStage0.standaloneFiles[idx]) || null",
            fidx,
        ).as_element()
    except Exception:
        return False
    if elem is None:
        return False
    try:
        elem.set_input_files(_choose_synthetic_upload(str(file_info.get("accept") or "")))
        return True
    except Exception:
        return False


def _crawl_actor_playwright(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    stage0_budget: _Stage0Budget,
    *,
    browser: Any,
    actor: str,
    start_urls: Sequence[str],
    forms_enabled: bool,
    actor_page_limit: int,
    actor_action_limit: int,
    timeout_ms: int,
    wait_ms: int,
    anon_request_context: Any = None,
) -> list[str]:
    """Run Layers 1-3 inside an isolated Playwright context for a single actor."""
    cookie_hdr, extra_headers = _extract_actor_browser_auth(http_client, actor)
    operator_headers = _operator_browser_headers(http_client)
    operator_override_names = frozenset(k.lower() for k in operator_headers)
    local_storage = _extract_actor_local_storage(http_client, actor)
    local_storage_by_origin = (
        _extract_actor_local_storage_by_origin(http_client, actor)
        if callable(_extract_actor_local_storage_by_origin)
        else {}
    )
    cookie_records = (
        _extract_actor_cookie_records(
            http_client,
            actor,
            base_url=http_client.base_url,
            fallback_cookie_hdr=cookie_hdr,
        )
        if callable(_extract_actor_cookie_records)
        else [
            {"name": cname, "value": cval, "url": http_client.base_url}
            for cname, cval in _parse_cookie_pairs(cookie_hdr)
        ]
    )
    try:
        actor_secrets = _collect_actor_secrets(
            http_client,
            cookie_hdr,
            extra_headers,
            local_storage=local_storage,
            cookie_records=cookie_records,
            local_storage_by_origin=local_storage_by_origin,
        )
    except TypeError:
        actor_secrets = _collect_actor_secrets(
            http_client,
            cookie_hdr,
            extra_headers,
            local_storage=local_storage,
        )
    base_actor_auth_header_names: set[str] = {
        k.strip().lower()
        for k in extra_headers
        if k and k.strip().lower() not in operator_override_names
    }
    actors_mgr = getattr(http_client, "actors", None)
    mgr_disc_hdr = str(getattr(actors_mgr, "discovered_auth_header", "") or "").strip().lower()
    if mgr_disc_hdr:
        base_actor_auth_header_names.add(mgr_disc_hdr)
    sensitive_fn = getattr(actors_mgr, "sensitive_header_names", None)
    if callable(sensitive_fn):
        for sh in sensitive_fn() or ():
            low_sh = str(sh or "").strip().lower()
            if low_sh and low_sh not in operator_override_names:
                base_actor_auth_header_names.add(low_sh)
    actor_obj = (getattr(actors_mgr, "actors", None) or {}).get(actor) if actors_mgr is not None else None
    if actor_obj is not None:
        for attr_name in ("auth_header_name", "auth_header", "csrf_header_name"):
            attr_val = str(getattr(actor_obj, attr_name, "") or "").strip().lower()
            if attr_val and attr_val not in operator_override_names:
                base_actor_auth_header_names.add(attr_val)
        for hmap_name in ("base_headers", "headers"):
            hmap = getattr(actor_obj, hmap_name, None)
            if isinstance(hmap, dict):
                for hk in hmap:
                    low_hk = str(hk or "").strip().lower()
                    if low_hk and low_hk not in operator_override_names:
                        base_actor_auth_header_names.add(low_hk)
    base_origin_parts = _normalized_origin_parts(http_client.base_url)

    context = browser.new_context(
        ignore_https_errors=True,
        service_workers="block",
        user_agent=_operator_user_agent(http_client, default_ua=_BROWSER_USER_AGENT),
    )
    session_dropped = False
    form_submitting_flag = [False]
    pending_redirect_urls: list[tuple[str, str]] = []

    try:
        if callable(_build_multi_origin_localstorage_init_script):
            ls_init_script = _build_multi_origin_localstorage_init_script(
                local_storage_by_origin,
                fallback_origin=http_client.base_url,
                fallback_local_storage=local_storage,
            )
        else:
            ls_init_script = _build_origin_localstorage_init_script(http_client.base_url, local_storage)
        if ls_init_script:
            context.add_init_script(ls_init_script)

        if cookie_records:
            context.add_cookies(cookie_records)

        def _on_ws_route(ws_route: Any) -> None:
            ws_url = str(getattr(ws_route, "url", "") or "")
            is_in_scope = collector.record_ws_endpoint(ws_url)
            try:
                if is_in_scope:
                    ws_route.close(code=1000, reason="stage0 recorded")
                else:
                    ws_route.close(code=1008, reason="out of scope")
            except Exception:
                pass

        if hasattr(context, "route_web_socket"):
            context.route_web_socket("**/*", _on_ws_route)

        def _stripped_anonymous_headers(req: Any) -> dict[str, str]:
            try:
                raw_hdrs = dict(req.all_headers() or {})
            except Exception:
                raw_hdrs = dict(getattr(req, "headers", None) or {})
            with collector._lock:
                disc_auth = {h.strip().lower() for h in collector.discovered_auth_headers if h}
            dyn_sensitive: set[str] = set()
            if callable(sensitive_fn):
                for sh in sensitive_fn() or ():
                    low_sh = str(sh or "").strip().lower()
                    if low_sh and low_sh not in operator_override_names:
                        dyn_sensitive.add(low_sh)
            blocked_low = _CDN_STRIPPED_AUTH_HEADERS | base_actor_auth_header_names | disc_auth | dyn_sensitive
            sanitized_raw = {
                str(k): str(v)
                for k, v in raw_hdrs.items()
                if k and not str(k).startswith(":") and str(k).strip().lower() not in blocked_low
            }
            safe_op_hdrs = {
                k: v
                for k, v in operator_headers.items()
                if str(k).strip().lower() not in blocked_low
            }
            if safe_op_hdrs:
                return _merge_browser_route_headers(
                    sanitized_raw,
                    safe_op_hdrs,
                    override_names=operator_override_names,
                )
            return sanitized_raw

        def _continue_route(
            route: Any,
            req: Any,
            *,
            include_extra_headers: bool,
            strip_auth_headers: bool = False,
        ) -> None:
            if strip_auth_headers:
                sanitized = _stripped_anonymous_headers(req)
                try:
                    route.continue_(headers=sanitized)
                except Exception:
                    pass
                return
            headers_to_apply = extra_headers if include_extra_headers else operator_headers
            if headers_to_apply:
                try:
                    raw_hdrs = dict(req.all_headers() or {})
                except Exception:
                    raw_hdrs = dict(getattr(req, "headers", None) or {})
                merged = _merge_browser_route_headers(
                    raw_hdrs,
                    headers_to_apply,
                    override_names=operator_override_names,
                )
                try:
                    route.continue_(headers=merged)
                except Exception:
                    pass
                return
            try:
                route.continue_()
            except Exception:
                pass

        def _continue_cdn_route_anonymously(route: Any, req: Any, cdn_url: str) -> None:
            """Fetch CDN JS strictly anonymously (cookie-free) when Playwright APIRequestContext is available."""
            if anon_request_context is not None and hasattr(route, "fulfill"):
                anon_hdrs = {
                    k: v
                    for k, v in _stripped_anonymous_headers(req).items()
                    if k.strip().lower() not in {"host", "content-length", "connection", "accept-encoding", "referer", "origin"}
                }
                curr_url = cdn_url
                try:
                    for _hop in range(3):
                        resp = anon_request_context.get(
                            curr_url,
                            headers=anon_hdrs,
                            timeout=min(timeout_ms, 8000),
                            max_redirects=0,
                        )
                        status_code = int(getattr(resp, "status", 0) or 0)
                        resp_hdrs = {str(k): str(v) for k, v in (getattr(resp, "headers", None) or {}).items()}
                        if 300 <= status_code < 400:
                            loc = next((v for k, v in resp_hdrs.items() if k.lower() == "location"), "")
                            next_url = urljoin(curr_url, loc) if loc else ""
                            if not next_url or not _is_allowed_cdn_script_url(next_url, http_client.base_url, req):
                                route.abort("blockedbyclient")
                                return
                            curr_url = next_url
                            continue
                        raw_body = bytes(resp.body() or b"")
                        if len(raw_body) > _MAX_CDN_JS_FULFILL_BYTES:
                            route.abort("blockedbyclient")
                            return
                        fulfill_hdrs = {
                            k: v
                            for k, v in resp_hdrs.items()
                            if k.lower() not in {"content-encoding", "content-length", "transfer-encoding"}
                        }
                        route.fulfill(status=status_code, headers=fulfill_hdrs, body=raw_body)
                        return
                    route.abort("blockedbyclient")
                    return
                except Exception:
                    try:
                        route.abort("failed")
                    except Exception:
                        pass
                    return
            _continue_route(route, req, include_extra_headers=False, strip_auth_headers=True)

        def _on_route(route: Any) -> None:
            req = route.request
            req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
            req_url = str(getattr(req, "url", "") or "")
            try:
                _clean, req_path, _q = _check_http_scope(http_client, req_url, allow_fragment=False)
            except ScopeViolationError:
                req_parts = _normalized_origin_parts(req_url)
                is_cross_origin = bool(
                    req_parts is not None
                    and (base_origin_parts is None or req_parts[:3] != base_origin_parts[:3])
                )
                if is_cross_origin:
                    if _is_allowed_cdn_script_url(req_url, http_client.base_url, req):
                        parsed_cdn = urlsplit(req_url.strip())
                        cdn_clean = urlunsplit(
                            (parsed_cdn.scheme.lower(), parsed_cdn.netloc, parsed_cdn.path or "/", parsed_cdn.query, "")
                        )
                        if collector.try_reserve_cdn_script_asset(cdn_clean):
                            _continue_cdn_route_anonymously(route, req, cdn_clean)
                            return
                    else:
                        res_type = str(getattr(req, "resource_type", "") or "").strip().lower()
                        if res_type in {"xhr", "fetch", "eventsource", "preflight"} or (
                            not res_type and not _is_heavy_media_url(req_url)
                        ):
                            collector.record_external_api_observation(req_url, req_method)
                try:
                    route.abort("blockedbyclient")
                except Exception:
                    pass
                return

            if not forms_enabled:
                if req_method not in _READONLY_METHODS:
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
            else:
                if req_method in _READONLY_METHODS:
                    pass
                elif req_method in _FORM_ALLOWED_WRITE_METHODS:
                    if (
                        req_method not in http_client.allowed_methods
                        or _DESTRUCTIVE_RE.search(req_path)
                        or is_virgin_state_sensitive_path(req_path)
                    ):
                        try:
                            route.abort("blockedbyclient")
                        except Exception:
                            pass
                        return
                else:
                    # DELETE and non-standard methods are never permitted during Stage 0 crawl.
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return

            is_static = is_static_asset_url(req_url) and not _extract_path_embedded_params(req_path)
            if is_static:
                if _is_heavy_media_url(req_url):
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
                _continue_route(route, req, include_extra_headers=False)
                return

            if req_method in {"GET", "HEAD"} and _is_browser_script_asset(req_url, req_path, req):
                if not collector.try_reserve_script_asset(_clean):
                    try:
                        route.abort("blockedbyclient")
                    except Exception:
                        pass
                    return
                _continue_route(route, req, include_extra_headers=True)
                return

            if not stage0_budget.try_consume():
                try:
                    route.abort("blockedbyclient")
                except Exception:
                    pass
                return

            _continue_route(route, req, include_extra_headers=True)

        context.route("**/*", _on_route)
        page = context.new_page()

        def _on_request(req: Any) -> None:
            req_url = str(getattr(req, "url", "") or "")
            req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
            try:
                _clean, req_path, _q = _check_http_scope(http_client, req_url, allow_fragment=False)
            except ScopeViolationError:
                return
            if is_static_asset_url(req_path) and not _extract_path_embedded_params(req_path):
                return
            if is_non_endpoint_source_path(req_path):
                return
            if req_method in {"GET", "HEAD"} and _is_browser_script_asset(req_url, req_path, req):
                return

            try:
                hdrs = dict(getattr(req, "headers", None) or {})
            except Exception:
                hdrs = {}
            blocked_app_hdrs = set(base_actor_auth_header_names) | set(operator_override_names)
            if callable(sensitive_fn):
                for sh in sensitive_fn() or ():
                    low_sh = str(sh or "").strip().lower()
                    if low_sh:
                        blocked_app_hdrs.add(low_sh)
            collector.record_observed_app_headers(hdrs, blocked_names=blocked_app_hdrs)
            ctype = str(hdrs.get("content-type") or hdrs.get("Content-Type") or "")

            post_data_text: str | None = None
            post_data_bytes: bytes | None = None
            try:
                raw_buf = getattr(req, "post_data_buffer", None)
                if isinstance(raw_buf, (bytes, bytearray)):
                    post_data_bytes = bytes(raw_buf)
            except Exception:
                post_data_bytes = None
            if post_data_bytes is None or "multipart/form-data" not in ctype.lower():
                try:
                    raw_pd = getattr(req, "post_data", None)
                    if isinstance(raw_pd, str):
                        post_data_text = raw_pd
                except Exception:
                    post_data_text = None

            params, body_tmpl, mp_schema, is_form_body = _extract_request_body_artifacts(
                ctype,
                post_data_text,
                post_data_bytes,
            )
            collector.network_requests_captured += 1
            collector.record_route(
                method=req_method,
                raw_url=req_url,
                params=params,
                is_form=is_form_body,
                body_template=body_tmpl,
                body_template_observed=bool(body_tmpl),
                multipart_schema=mp_schema,
            )

        def _on_response(resp: Any) -> None:
            nonlocal session_dropped
            resp_url = str(getattr(resp, "url", "") or "")
            req_obj = getattr(resp, "request", None)
            is_cdn_script = False
            try:
                _clean, resp_path, _q = _check_http_scope(http_client, resp_url, allow_fragment=False)
            except ScopeViolationError:
                resp_parts = _normalized_origin_parts(resp_url)
                is_cross_origin = bool(
                    resp_parts is not None
                    and (base_origin_parts is None or resp_parts[:3] != base_origin_parts[:3])
                )
                if not is_cross_origin:
                    return
                parsed_cdn_resp = urlsplit(resp_url.strip())
                cdn_resp_clean = urlunsplit(
                    (
                        parsed_cdn_resp.scheme.lower(),
                        parsed_cdn_resp.netloc,
                        parsed_cdn_resp.path or "/",
                        parsed_cdn_resp.query,
                        "",
                    )
                )
                if not (
                    _is_allowed_cdn_script_url(resp_url, http_client.base_url, req_obj)
                    or collector.is_reserved_cdn_script(cdn_resp_clean)
                ):
                    return
                is_cdn_script = True
                resp_path = parsed_cdn_resp.path or "/"

            status = int(getattr(resp, "status", 0) or 0)
            req_method = str(getattr(req_obj, "method", "GET") or "GET").strip().upper()
            try:
                resp_headers = {str(k): str(v) for k, v in (getattr(resp, "headers", None) or {}).items()}
            except Exception:
                resp_headers = {}
            ctype = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "").lower()
            loc_hdr = str(resp_headers.get("location") or resp_headers.get("Location") or "")

            if is_cdn_script:
                if status < 200 or status >= 300 or "html" in ctype:
                    return
                low_cdn_path = resp_path.lower()
                is_cdn_js = (
                    "javascript" in ctype
                    or "ecmascript" in ctype
                    or low_cdn_path.endswith((".js", ".mjs", ".cjs"))
                )
                if not is_cdn_js:
                    return
                try:
                    raw_cdn_body = resp.body()
                except Exception:
                    return
                if not raw_cdn_body:
                    return
                text_cdn_body = bytes(raw_cdn_body[:_MAX_JS_CHUNK_BYTES]).decode("utf-8", errors="replace")
                if text_cdn_body.lstrip().lower().startswith(("<!doctype html", "<html")):
                    return
                collector.record_document(
                    url=resp_url,
                    content_type=ctype or "application/javascript",
                    body=text_cdn_body,
                    headers=resp_headers,
                    is_js=True,
                    is_css=False,
                    is_cdn_js=True,
                )
                return

            # Session-drop guard for authenticated form crawling.
            if actor != "anon" and forms_enabled and form_submitting_flag[0]:
                if status == 401 or (
                    300 <= status < 400 and loc_hdr and _AUTH_FORM_RE.search(urlsplit(loc_hdr).path or "")
                ):
                    session_dropped = True

            if loc_hdr and collector._allow_canonical_host_aliases:
                loc_hosts = detect_internal_canonical_hosts(
                    "",
                    base_url=http_client.base_url,
                    location_header=loc_hdr,
                )
                if loc_hosts:
                    collector.register_canonical_hosts(loc_hosts)
                rewritten_loc = collector.rewrite_canonical_url(loc_hdr)
                if rewritten_loc != loc_hdr:
                    collector.record_route(method="GET", raw_url=rewritten_loc, current_url=resp_url)
                    pending_redirect_urls.append((rewritten_loc, resp_url))

            is_script_asset = req_method in {"GET", "HEAD"} and _is_browser_script_asset(
                resp_url,
                resp_path,
                req_obj,
            )
            if not is_script_asset:
                collector.record_route(
                    method=req_method,
                    raw_url=resp_url,
                    status=status,
                )

            if status < 200 or status >= 300:
                return
            low_resp_path = resp_path.lower()
            is_js = (
                "javascript" in ctype
                or "ecmascript" in ctype
                or low_resp_path.endswith((".js", ".mjs", ".cjs"))
            )
            is_css = ("css" in ctype) or low_resp_path.endswith(".css")
            is_html = "html" in ctype
            is_spec_candidate = (
                not is_js
                and not is_css
                and not is_html
                and any(tok in low_resp_path for tok in ("openapi", "swagger", "api-docs"))
                and (
                    "json" in ctype
                    or "yaml" in ctype
                    or "yml" in ctype
                    or "text/plain" in ctype
                    or low_resp_path.endswith((".json", ".yaml", ".yml"))
                )
            )
            if not is_js and not is_css and not is_html and not is_spec_candidate:
                return
            max_bytes = (
                _MAX_OPENAPI_SPEC_BYTES
                if is_spec_candidate
                else (_MAX_JS_CHUNK_BYTES if is_js else (_MAX_CSS_BYTES if is_css else _MAX_HTML_BYTES))
            )
            try:
                raw_body = resp.body()
            except Exception:
                return
            if not raw_body:
                return
            text_body = bytes(raw_body[:max_bytes]).decode("utf-8", errors="replace")
            if is_spec_candidate:
                parsed_doc = _parse_openapi_spec_document(
                    text_body,
                    content_type=ctype,
                    path=resp_path,
                )
                if parsed_doc is not None:
                    spec_key = _scoped_storage_key(resp_url, http_client.base_url)
                    with collector._lock:
                        if spec_key not in collector.captured_specs and len(collector.captured_specs) < 16:
                            collector.captured_specs[spec_key] = (resp_url, parsed_doc)
                return
            if is_html and collector._allow_canonical_host_aliases:
                collector.register_canonical_hosts(
                    detect_internal_canonical_hosts(
                        text_body,
                        base_url=http_client.base_url,
                        location_header=loc_hdr,
                    )
                )
            collector.record_document(
                url=resp_url,
                content_type=ctype,
                body=text_body,
                headers=resp_headers,
                is_js=is_js,
                is_css=is_css,
            )

        def _on_websocket(ws: Any) -> None:
            ws_url = str(getattr(ws, "url", "") or "")
            collector.record_ws_endpoint(ws_url)

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("websocket", _on_websocket)

        queue: deque[str] = deque()
        seo_queue: deque[str] = deque()
        queued_urls: set[str] = set()
        visited_urls: set[str] = set()
        template_visit_counts: dict[tuple[str, frozenset[str], str], int] = {}
        seo_bfs_counts: dict[str, int] = {}
        seen_dom_states: set[tuple[str, str, str]] = set()
        submitted_forms: set[tuple[Any, ...]] = set()
        actor_pages_visited = 0
        actor_actions_taken = 0

        def _scoped_bfs_template_key(
            url_str: str,
            norm_path_str: str,
            query_str: str,
            frag_str: str,
        ) -> tuple[str, frozenset[str], str]:
            q_keys = frozenset(k for k, _ in parse_qsl(query_str, keep_blank_values=True) if k)
            tmpl_path = route_template_of(norm_path_str)
            u_parts = _normalized_origin_parts(url_str)
            is_cross = bool(
                u_parts is not None
                and base_origin_parts is not None
                and u_parts[:3] != base_origin_parts[:3]
            )
            scoped_tmpl = f"{u_parts[3]}{tmpl_path}" if (is_cross and u_parts is not None) else tmpl_path
            return (scoped_tmpl, q_keys, _normalize_hash_route(f"#{frag_str}" if frag_str else ""))

        def _enqueue_url(raw_candidate: str, current_page_url: str, *, allow_seo_front: bool = False) -> None:
            cand = str(raw_candidate or "").strip()
            if not cand or cand.lower().startswith(_NON_HTTP_SCHEMES):
                return
            cand = collector.rewrite_canonical_url(cand)
            if cand.startswith("#/"):
                cur_no_frag = urlsplit(current_page_url)
                base_for_hash = urlunsplit((cur_no_frag.scheme, cur_no_frag.netloc, cur_no_frag.path or "/", cur_no_frag.query, ""))
                resolved_cand = f"{base_for_hash}{cand}"
            else:
                cand = normalize_bare_hostport_url(cand, base=current_page_url)
                if not cand or is_port_in_path_artifact(cand, origin_url=http_client.base_url):
                    return
                resolved_cand = urljoin(current_page_url, cand)
            try:
                full_u, path_u, query_u = _check_http_scope(http_client, resolved_cand, allow_fragment=True)
            except ScopeViolationError:
                return
            try:
                norm_p = normalize_path(path_u or "/")
            except ValueError:
                return
            if (
                has_double_slash_path(path_u)
                or is_static_asset_url(norm_p)
                or is_non_endpoint_source_path(norm_p)
                or _is_stage0_noise_path(norm_p, origin_url=http_client.base_url)
                or norm_p.lower().endswith(_SCRIPT_ASSET_EXTS)
                or is_logout_route(norm_p)
                or is_destructive_lifecycle_route(norm_p)
            ):
                return
            if actor != "anon" and _DESTRUCTIVE_RE.search(norm_p):
                return
            if full_u in queued_urls or full_u in visited_urls:
                return
            frag = urlsplit(full_u).fragment
            tmpl_key = _scoped_bfs_template_key(full_u, norm_p, query_u, frag)
            if template_visit_counts.get(tmpl_key, 0) >= _MAX_VISITS_PER_TEMPLATE:
                return
            seo_cls = _classify_seo_route_pattern(norm_p)
            if seo_cls and not allow_seo_front:
                if seo_bfs_counts.get(seo_cls, 0) >= _MAX_SEO_BFS_VISITS_PER_PATTERN:
                    return
                seo_bfs_counts[seo_cls] = seo_bfs_counts.get(seo_cls, 0) + 1
                queued_urls.add(full_u)
                seo_queue.append(full_u)
                return
            queued_urls.add(full_u)
            queue.append(full_u)

        for start_u in start_urls:
            _enqueue_url(start_u, http_client.base_url, allow_seo_front=True)

        def _dom_link_base(dom_data: dict[str, Any], current_page_url: str) -> str:
            raw_base_uri = str(dom_data.get("base_uri") or "").strip()
            if not raw_base_uri:
                return current_page_url
            raw_base_uri = collector.rewrite_canonical_url(raw_base_uri)
            try:
                clean_b, _bp, _bq = _check_http_scope(http_client, raw_base_uri, allow_fragment=False)
                return clean_b
            except ScopeViolationError:
                return current_page_url

        def _ingest_dom_discovery(dom_data: dict[str, Any], current_page_url: str) -> None:
            if collector._allow_canonical_host_aliases:
                collector.register_canonical_hosts(
                    _detect_canonical_hosts_from_dom(dom_data, base_url=http_client.base_url)
                )
            link_base = _dom_link_base(dom_data, current_page_url)
            for link_raw in dom_data.get("links") or ():
                rewritten_link = collector.rewrite_canonical_url(str(link_raw))
                collector.record_route(method="GET", raw_url=rewritten_link, current_url=link_base)
                _enqueue_url(rewritten_link, link_base)
            for h_raw in dom_data.get("hash_routes") or ():
                _enqueue_url(str(h_raw), current_page_url)
            for form_item in dom_data.get("forms") or ():
                if not isinstance(form_item, dict):
                    continue
                raw_action = str(form_item.get("action") or "").strip()
                rewritten_action = collector.rewrite_canonical_url(raw_action) if raw_action else ""
                f_action = rewritten_action or current_page_url
                f_base = link_base if rewritten_action else current_page_url
                f_method = str(form_item.get("method") or "GET").upper()
                f_fields = [
                    str(fld.get("name") or "")
                    for fld in (form_item.get("fields") or ())
                    if isinstance(fld, dict) and fld.get("name")
                ]
                collector.record_route(
                    method=f_method,
                    raw_url=f_action,
                    current_url=f_base,
                    params=f_fields,
                    is_form=True,
                )
                if (
                    f_method == "GET"
                    and rewritten_action
                    and not _DESTRUCTIVE_RE.search(rewritten_action)
                ):
                    _enqueue_url(f_action, f_base)

        def _run_layer3_on_dom(dom_data: dict[str, Any], current_page_url: str) -> None:
            nonlocal session_dropped
            if not forms_enabled or session_dropped or not stage0_budget.can_spend():
                return
            try:
                page_path = normalize_path(urlsplit(current_page_url).path or "/")
            except ValueError:
                page_path = "/"

            # 1. Standalone input[type="file"] outside <form>
            for finp in dom_data.get("standalone_files") or ():
                if session_dropped or not stage0_budget.can_spend():
                    break
                if not isinstance(finp, dict):
                    continue
                fhay = f"{finp.get('name', '')} {finp.get('id', '')} {finp.get('aria_label', '')}"
                if _DESTRUCTIVE_RE.search(fhay):
                    continue
                fsig = (
                    actor,
                    "standalone_file",
                    page_path,
                    str(finp.get("name") or ""),
                    str(finp.get("id") or ""),
                    str(finp.get("accept") or ""),
                )
                if fsig in submitted_forms:
                    continue
                submitted_forms.add(fsig)
                form_submitting_flag[0] = True
                try:
                    if _trigger_standalone_file_input(page, finp):
                        collector.uploads_triggered += 1
                        if wait_ms > 0:
                            page.wait_for_timeout(max(150, wait_ms))
                finally:
                    form_submitting_flag[0] = False

            # 2. Visible <form> elements
            link_base = _dom_link_base(dom_data, current_page_url)
            forms_list = [f for f in (dom_data.get("forms") or ()) if isinstance(f, dict) and f.get("visible")]
            for form_item in forms_list:
                if session_dropped or not stage0_budget.can_spend():
                    break
                raw_action = str(form_item.get("action") or "").strip()
                rewritten_raw_action = collector.rewrite_canonical_url(raw_action) if raw_action else ""
                was_rewritten_action = bool(raw_action and rewritten_raw_action != raw_action)
                resolved_action = urljoin(link_base, rewritten_raw_action) if rewritten_raw_action else current_page_url
                try:
                    _a_url, a_path, _a_q = _check_http_scope(http_client, resolved_action, allow_fragment=False)
                    norm_action_path = normalize_path(a_path or "/")
                except (ScopeViolationError, ValueError):
                    continue
                f_method = str(form_item.get("method") or "GET").strip().upper() or "GET"
                if f_method == "DELETE":
                    continue
                if f_method in _FORM_ALLOWED_WRITE_METHODS and f_method not in http_client.allowed_methods:
                    continue

                raw_fields = [fld for fld in (form_item.get("fields") or ()) if isinstance(fld, dict)]
                haystack = " ".join([
                    norm_action_path,
                    str(form_item.get("id") or ""),
                    str(form_item.get("name") or ""),
                    str(form_item.get("aria_label") or ""),
                    str(form_item.get("text") or ""),
                ])
                if _DESTRUCTIVE_RE.search(haystack):
                    continue
                if should_skip_stage0_form_submit(resolved_action, current_page_url):
                    continue
                has_pw_input = any(str(fld.get("type") or "").lower() == "password" for fld in raw_fields)
                if actor != "anon" and (_AUTH_FORM_RE.search(haystack) or has_pw_input):
                    continue

                field_sig = tuple(
                    sorted(
                        (str(fld.get("name") or ""), str(fld.get("type") or ""))
                        for fld in raw_fields
                    )
                )
                form_sig = (actor, "form", page_path, norm_action_path, f_method, field_sig)
                if form_sig in submitted_forms:
                    continue
                submitted_forms.add(form_sig)

                before_url = str(page.url or current_page_url)
                form_submitting_flag[0] = True
                try:
                    submitted, uploaded = _fill_and_submit_form(
                        page,
                        form_item,
                        timeout_ms=timeout_ms,
                        rewritten_action=_a_url if was_rewritten_action else "",
                    )
                    if submitted:
                        collector.forms_submitted += 1
                        if uploaded:
                            collector.uploads_triggered += 1
                        if wait_ms > 0:
                            page.wait_for_timeout(max(150, wait_ms))
                finally:
                    form_submitting_flag[0] = False

                after_url = str(page.url or before_url)
                if after_url != before_url:
                    _enqueue_url(after_url, before_url)
                    # Return to the original page only if more forms remain to be submitted on it.
                    if len(forms_list) > 1 and stage0_budget.can_spend() and not session_dropped:
                        try:
                            page.goto(before_url, wait_until="domcontentloaded", timeout=timeout_ms)
                            if wait_ms > 0:
                                page.wait_for_timeout(min(250, wait_ms))
                            page.evaluate(_COLLECT_DOM_STATE_JS)
                        except Exception:
                            break

        while (queue or seo_queue) and actor_pages_visited < actor_page_limit and stage0_budget.can_spend():
            target_url = queue.popleft() if queue else seo_queue.popleft()
            if target_url in visited_urls:
                continue
            parsed_t = urlsplit(target_url)
            try:
                norm_t_path = normalize_path(parsed_t.path or "/")
            except ValueError:
                continue
            tmpl_key = _scoped_bfs_template_key(target_url, norm_t_path, parsed_t.query, parsed_t.fragment)
            if template_visit_counts.get(tmpl_key, 0) >= _MAX_VISITS_PER_TEMPLATE:
                continue

            visited_urls.add(target_url)
            template_visit_counts[tmpl_key] = template_visit_counts.get(tmpl_key, 0) + 1
            actor_pages_visited += 1
            collector.pages_visited += 1

            goto_failed = False
            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)
            except Exception:
                goto_failed = True

            if pending_redirect_urls:
                for redir_u, redir_ref in pending_redirect_urls:
                    _enqueue_url(redir_u, redir_ref)
                pending_redirect_urls.clear()

            if goto_failed:
                continue

            final_url = str(page.url or target_url)
            try:
                _check_http_scope(http_client, final_url, allow_fragment=True)
            except ScopeViolationError:
                continue

            try:
                dom_data = page.evaluate(_COLLECT_DOM_STATE_JS)
            except Exception:
                continue
            if not isinstance(dom_data, dict):
                continue

            # If a modern SPA shell (Vue/Vite/React) has not mounted links/forms/controls yet,
            # give module scripts one bounded settle opportunity before collecting controls.
            if (
                not (dom_data.get("controls") or ())
                and not (dom_data.get("links") or ())
                and not (dom_data.get("forms") or ())
                and not (dom_data.get("hash_routes") or ())
            ):
                try:
                    page.wait_for_load_state("load", timeout=min(1500, timeout_ms))
                except Exception:
                    pass
                if wait_ms > 0:
                    try:
                        page.wait_for_timeout(min(1000, max(wait_ms, 300)))
                    except Exception:
                        pass
                try:
                    refreshed_dom = page.evaluate(_COLLECT_DOM_STATE_JS)
                    if isinstance(refreshed_dom, dict):
                        dom_data = refreshed_dom
                        final_url = str(page.url or final_url)
                except Exception:
                    pass

            canon_path = _scoped_storage_key(final_url, http_client.base_url)
            frag_part = urlsplit(final_url).fragment
            canon_with_hash = f"{canon_path}#{frag_part}" if frag_part.startswith("/") else canon_path
            dom_hash = _compute_dom_state_hash(dom_data)
            state_key = (actor, canon_with_hash, dom_hash)
            if state_key in seen_dom_states:
                continue
            seen_dom_states.add(state_key)
            collector.dom_states_seen += 1

            _ingest_dom_discovery(dom_data, final_url)
            _run_layer3_on_dom(dom_data, final_url)

            def _prioritize_controls(raw_controls: Any) -> list[dict[str, Any]]:
                items = [c for c in (raw_controls or ()) if isinstance(c, dict)]
                return sorted(
                    items,
                    key=lambda c: (
                        0
                        if (
                            c.get("nav_trigger")
                            or str(c.get("role") or "") in {"tab", "menuitem"}
                            or bool(c.get("aria_controls"))
                            or bool(c.get("aria_expanded"))
                        )
                        else 1
                    ),
                )

            # Explore safe non-destructive controls on this page up to actor_action_limit.
            clicked_on_page: set[tuple[str, str, str, str]] = set()
            controls_queue = _prioritize_controls(dom_data.get("controls"))
            ctrl_cursor = 0
            while (
                ctrl_cursor < len(controls_queue)
                and actor_actions_taken < actor_action_limit
                and stage0_budget.can_spend()
            ):
                ctrl = controls_queue[ctrl_cursor]
                ctrl_cursor += 1
                if not isinstance(ctrl, dict):
                    continue
                ctrl_hay = " ".join([
                    str(ctrl.get("label") or ""),
                    str(ctrl.get("title") or ""),
                    str(ctrl.get("tooltip") or ""),
                    str(ctrl.get("id") or ""),
                    str(ctrl.get("name") or ""),
                    str(ctrl.get("aria_controls") or ""),
                    str(ctrl.get("onclick") or ""),
                ])
                if _DESTRUCTIVE_RE.search(ctrl_hay):
                    continue
                if actor != "anon" and _AUTH_NAV_RE.search(ctrl_hay):
                    continue
                # Skip already-selected tabs so we click unselected tabs first.
                if str(ctrl.get("role") or "") == "tab" and str(ctrl.get("aria_selected") or "") == "true":
                    continue
                norm_label = _normalize_volatile_text(str(ctrl.get("label") or ""))
                ctrl_id = str(ctrl.get("id") or "")
                ctrl_ac = str(ctrl.get("aria_controls") or "")
                disambig = norm_label or ctrl_id or ctrl_ac or (
                    f"{str(ctrl.get('class_hint') or '')[:48]}#{int(ctrl.get('ctrl_index', -1))}"
                )
                ctrl_fp = (
                    str(ctrl.get("role") or ctrl.get("tag") or ""),
                    ctrl_id,
                    ctrl_ac,
                    disambig,
                )
                if ctrl_fp in clicked_on_page:
                    continue
                clicked_on_page.add(ctrl_fp)

                c_idx = int(ctrl.get("ctrl_index", -1))
                if c_idx < 0:
                    continue
                try:
                    clicked_ok = page.evaluate(
                        """idx => {
                          const els = window.__kryonStage0 && window.__kryonStage0.controls;
                          const el = els && els[idx];
                          if (!el || !el.isConnected || el.disabled || el.getAttribute('aria-disabled') === 'true') {
                            return false;
                          }
                          if (typeof el.click === 'function') {
                            el.click();
                            return true;
                          }
                          el.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
                          return true;
                        }""",
                        c_idx,
                    )
                except Exception:
                    clicked_ok = False
                if not clicked_ok:
                    continue

                actor_actions_taken += 1
                collector.ui_actions_taken += 1
                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)

                after_click_url = str(page.url or final_url)
                try:
                    _check_http_scope(http_client, after_click_url, allow_fragment=True)
                except ScopeViolationError:
                    break

                if after_click_url != final_url:
                    try:
                        nav_dom = page.evaluate(_COLLECT_DOM_STATE_JS)
                        if isinstance(nav_dom, dict):
                            _ingest_dom_discovery(nav_dom, after_click_url)
                    except Exception:
                        pass
                    _enqueue_url(after_click_url, final_url)
                    # Stop clicking stale controls from previous URL; BFS will visit the new URL.
                    break

                try:
                    new_dom = page.evaluate(_COLLECT_DOM_STATE_JS)
                except Exception:
                    break
                if not isinstance(new_dom, dict):
                    break
                new_hash = _compute_dom_state_hash(new_dom)
                new_state_key = (actor, canon_with_hash, new_hash)
                # Refresh remaining controls indices from the latest DOM snapshot.
                controls_queue = _prioritize_controls(new_dom.get("controls"))
                ctrl_cursor = 0
                if new_state_key not in seen_dom_states:
                    seen_dom_states.add(new_state_key)
                    collector.dom_states_seen += 1
                    _ingest_dom_discovery(new_dom, after_click_url)
                    _run_layer3_on_dom(new_dom, after_click_url)

        if session_dropped:
            _try_reauthenticate_actor(http_client, actor)
    finally:
        try:
            context.close()
        except Exception:
            pass

    return actor_secrets


_INLINE_HTML_SCRIPT_RE = re.compile(
    r"<script\b([^>]*)>([\s\S]*?)</script>",
    re.IGNORECASE,
)


def _scan_document_for_external_api_hosts(
    collector: _Stage0Collector,
    body_text: str,
    *,
    doc_url: str,
    is_js: bool,
) -> None:
    """Scan HTML/SSR configs or JS chunks for sibling/external API hosts and multi-origin routes."""
    if not body_text:
        return
    base_parts = _normalized_origin_parts(collector.http.base_url)
    if base_parts is None:
        return
    base_scheme, base_host, base_port, _base_origin = base_parts
    base_reg = _registrable_domain(base_host)
    base_is_loopback = is_loopback_or_private_base_url(collector.http.base_url)

    discovered_candidates: list[tuple[str, str]] = []
    seen_url_methods: dict[str, set[str]] = {}
    explicit_call_urls: set[str] = set()

    def _add_candidate(method: str, raw_u: str, *, explicit_call: bool = False) -> None:
        cleaned = str(raw_u or "").strip().rstrip(".,;:!?)'\"`")
        if "${" in cleaned:
            cleaned = re.sub(r"\$\{[^}]+\}", "{id}", cleaned)
        if not cleaned or len(cleaned) > 1024:
            return
        m = str(method or "GET").strip().upper()
        if m not in _VALID_HTTP_METHODS:
            m = "GET"
        if explicit_call:
            explicit_call_urls.add(cleaned)
        existing = seen_url_methods.setdefault(cleaned, set())
        if m not in existing:
            existing.add(m)
            discovered_candidates.append((m, cleaned))

    scan_text = body_text[:_MAX_JS_CHUNK_BYTES]
    if is_js:
        for fm in _JS_FETCH_ABS_URL_RE.finditer(scan_text):
            tail_window = scan_text[fm.end() : fm.end() + 260]
            # Bound method search to the current fetch(...) call arguments before the next statement/fetch.
            next_call = re.search(r"\b(?:fetch|axios)\s*[.(]|;", tail_window)
            tail = tail_window[: next_call.start()] if next_call else tail_window
            mm = _JS_FETCH_METHOD_OPT_RE.search(tail)
            _add_candidate(mm.group(2) if mm else "GET", fm.group(2), explicit_call=True)
        for am in _JS_AXIOS_METHOD_ABS_URL_RE.finditer(scan_text):
            _add_candidate(am.group(1), am.group(3), explicit_call=True)

    for um in _ABS_HTTP_URL_RE.finditer(scan_text):
        raw_found = um.group(0).strip().rstrip(".,;:!?)'\"`")
        if "${" in raw_found:
            raw_found = re.sub(r"\$\{[^}]+\}", "{id}", raw_found)
        if raw_found and raw_found not in seen_url_methods:
            _add_candidate("GET", raw_found, explicit_call=False)
        if len(discovered_candidates) >= 240:
            break

    for cand_method, cand_url in discovered_candidates:
        parts = _normalized_origin_parts(cand_url)
        if parts is None:
            continue
        c_scheme, c_host, c_port, _c_origin = parts
        if (c_scheme, c_host, c_port) == (base_scheme, base_host, base_port):
            continue
        if _is_link_local_metadata_host(c_host):
            continue
        if not base_is_loopback and _is_non_public_or_internal_host(c_host):
            continue
        if _is_tracker_or_telemetry_host(c_host) or _host_matches_domain_set(c_host, _KNOWN_NON_API_DOC_HOSTS):
            continue

        parsed = urlsplit(cand_url)
        c_path = parsed.path or "/"
        low_path = c_path.lower()
        is_static_file = (
            _is_heavy_media_url(cand_url)
            or is_static_asset_url(c_path)
            or low_path.endswith((".js", ".mjs", ".cjs", ".css", ".map", ".svg"))
        )
        if is_static_file and not _API_PATH_RE.search(low_path):
            continue

        c_reg = _registrable_domain(c_host)
        is_sibling_domain = bool(
            (base_reg and c_reg and c_reg == base_reg and not base_is_loopback)
            or (base_is_loopback and c_host == base_host and c_port != base_port)
        )
        first_label = c_host.split(".", 1)[0] if "." in c_host else c_host
        is_root_only = c_path in {"", "/"}
        has_api_path = bool(_API_PATH_RE.search(low_path)) or any(
            tok in low_path for tok in ("/graphql", "/oauth", "/token", "/auth", "/login", "/checkout", "/cart")
        )
        is_explicit_call = cand_url in explicit_call_urls

        if is_sibling_domain:
            if is_root_only and first_label in _STATIC_CDN_SUBDOMAIN_PREFIXES:
                continue
            if not is_js and not is_explicit_call and not is_root_only and not has_api_path:
                if first_label not in _API_SUBDOMAIN_HINTS:
                    continue
            collector.record_external_api_observation(cand_url, cand_method)
        elif is_js and (is_explicit_call or has_api_path):
            collector.record_external_api_observation(cand_url, cand_method)

        # If multi-origin scope permits this URL, also record it as an accepted route.
        collector.record_route(
            method=cand_method,
            raw_url=cand_url,
            current_url=doc_url,
        )


def _fetch_cdn_sourcemap_anonymously(
    http_client: AgenticHTTPClient,
    map_url: str,
    *,
    referrer_url: str = "",
    stage0_budget: _Stage0Budget | None = None,
) -> str:
    """Fetch a safe, read-only CDN ``.map`` file strictly anonymously (cookie-free, TLS-verified, 1 MiB cap)."""
    if _requests is None:
        return ""
    scope_guard = getattr(http_client, "scope_guard", None)
    eff_referrer = str(referrer_url or map_url).strip()
    curr_url = map_url
    hdrs = {
        "Accept": "application/json, */*",
        "User-Agent": _operator_user_agent(http_client, default_ua=_BROWSER_USER_AGENT),
    }
    sess = _requests.Session()
    sess.trust_env = False
    try:
        for hop in range(3):
            if not _is_allowed_cdn_sourcemap_url(
                curr_url,
                http_client.base_url,
                referrer_url=eff_referrer,
                scope_guard=scope_guard,
                resolve_dns=True,
                fail_closed_on_dns_error=True,
            ):
                return ""
            if stage0_budget is not None:
                if not stage0_budget.try_consume(include_reserve=True):
                    return ""
            else:
                wire_budget = getattr(http_client, "budget", None)
                consume_fn = getattr(wire_budget, "consume", None)
                if callable(consume_fn):
                    allowed, _reason = consume_fn()
                    if not allowed:
                        return ""
            acquire_slot = getattr(http_client, "_acquire_rate_limit_slot", None)
            if callable(acquire_slot):
                acquire_slot()
            try:
                resp = sess.get(
                    curr_url,
                    headers=hdrs,
                    timeout=6.0,
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
            except Exception:
                return ""
            try:
                status_code = int(getattr(resp, "status_code", 0) or 0)
                if 300 <= status_code < 400:
                    if hop >= 2:
                        return ""
                    loc = str(resp.headers.get("Location") or resp.headers.get("location") or "").strip()
                    next_url = urljoin(curr_url, loc) if loc else ""
                    if not next_url:
                        return ""
                    curr_url = next_url
                    continue
                if status_code < 200 or status_code >= 300:
                    return ""
                raw_cl = str(resp.headers.get("Content-Length") or "").strip()
                if raw_cl.isdigit() and int(raw_cl) > _MAX_SOURCEMAP_BYTES:
                    return ""
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > _MAX_SOURCEMAP_BYTES:
                        return ""
                    chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")
            except Exception:
                return ""
            finally:
                try:
                    resp.close()
                except Exception:
                    pass
    finally:
        try:
            sess.close()
        except Exception:
            pass
    return ""


def _decode_and_ingest_sourcemap(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    raw_map: Any,
    *,
    source_url: str,
    is_cdn: bool = False,
    in_scope_assets: Sequence[str] = (),
    out_of_scope_assets: Sequence[str] = (),
    canonical_hosts: set[str] | None = None,
) -> bool:
    """Decode a Source Map v3 payload via ``kryon_core.js.sourcemap.parse_source_map`` and extract routes."""
    if _parse_source_map is None or not raw_map:
        return False
    if isinstance(raw_map, str):
        m_inline = _INLINE_SOURCEMAP_DATA_RE.fullmatch(raw_map.strip())
        if m_inline:
            norm_b64 = _normalize_inline_sourcemap_b64(m_inline.group(1))
            if not norm_b64:
                return False
            raw_map = f"data:application/json;base64,{norm_b64}"
    try:
        meta, contents = _parse_source_map(raw_map)
    except Exception:
        return False
    if not isinstance(meta, dict) or not meta.get("valid"):
        return False

    with collector._lock:
        collector.source_maps_parsed += 1

    raw_sources = meta.get("sources")
    sources: list[Any] = raw_sources if isinstance(raw_sources, list) else []
    indexed_pairs: list[tuple[int, str, str]] = []
    for idx_s, src_content in enumerate(contents or ()):
        if not isinstance(src_content, str) or not src_content.strip():
            continue
        src_name = str(sources[idx_s]) if idx_s < len(sources) else f"src-{idx_s}.js"
        is_vendor = "node_modules/" in src_name.lower() or "webpack/runtime" in src_name.lower()
        indexed_pairs.append((1 if is_vendor else 0, src_name, src_content))
    indexed_pairs.sort(key=lambda item: item[0])

    summary_doc_url = source_url
    summary_source_url = source_url
    if is_cdn:
        doc_path = urlsplit(source_url).path or "/sourcemap-bundle.js"
        summary_doc_url = urljoin(http_client.base_url, doc_path)
        summary_source_url = http_client.base_url

    total_chars = 0
    files_processed = 0
    for _prio, _src_name, src_text in indexed_pairs:
        if files_processed >= _MAX_SOURCEMAP_FILES_PER_MAP or total_chars >= _MAX_SOURCEMAP_TOTAL_CHARS:
            break
        remaining_chars = _MAX_SOURCEMAP_TOTAL_CHARS - total_chars
        snippet = src_text[: min(_MAX_SOURCEMAP_CONTENT_CHARS, remaining_chars)]
        if not snippet.strip():
            continue
        files_processed += 1
        total_chars += len(snippet)
        if canonical_hosts:
            snippet = rewrite_internal_canonical_urls_in_text(
                snippet,
                base_url=http_client.base_url,
                canonical_hosts=canonical_hosts,
            )
        _scan_document_for_external_api_hosts(
            collector,
            snippet,
            doc_url=source_url,
            is_js=True,
        )
        lazy_info = _extract_lazy_spa_routes_and_chunks(
            snippet,
            doc_url=summary_source_url,
            base_url=http_client.base_url,
        )
        for spa_r in lazy_info["routes"]:
            collector.record_route(method="GET", raw_url=spa_r, current_url=summary_source_url)
        if lazy_info["chunks"]:
            collector.record_lazy_chunks(lazy_info["chunks"])

        fake_rec = {
            "receipt_id": f"stage0-smap-{collector.source_maps_parsed}-{files_processed}",
            "url": summary_doc_url,
            "content_type": "application/javascript",
            "body": snippet,
            "response_headers": {},
            "redirect_location": "",
        }
        try:
            summary = _extract_surface_summary(
                fake_rec,
                http_client.base_url,
                in_scope_assets=in_scope_assets,
                out_of_scope_assets=out_of_scope_assets,
            )
            collector.ingest_surface_summary(summary, source_url=summary_source_url)
        except Exception:
            continue
    return True


def _run_layer4_passive_fusion(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    stage0_budget: _Stage0Budget,
    *,
    primary_actor: str,
    max_passive_probes: int,
    skip_probe_paths: Sequence[str] | None = None,
    start_paths: Sequence[str] | None = None,
) -> None:
    """Fuse captured HTML, JS chunks, source maps, and CSS via ``_extract_surface_summary`` and run bounded manifest probes."""
    if collector._allow_canonical_host_aliases:
        for doc in list(collector.captured_html.values()):
            hdrs = doc.get("headers") or {}
            loc_hdr = str(hdrs.get("location") or hdrs.get("Location") or "")
            collector.register_canonical_hosts(
                detect_internal_canonical_hosts(
                    str(doc.get("body") or ""),
                    base_url=http_client.base_url,
                    location_header=loc_hdr,
                )
            )
    canonical_hosts = collector.canonical_hosts_snapshot()
    base_origin_parts = _normalized_origin_parts(http_client.base_url)
    scope_guard = getattr(http_client, "scope_guard", None)
    in_scope_assets = tuple(getattr(scope_guard, "in_scope_assets", ()) or ())
    out_of_scope_assets = tuple(getattr(scope_guard, "out_of_scope_assets", ()) or ())

    pending_external_sourcemaps: list[tuple[str, bool, str]] = []
    seen_external_sourcemaps: set[str] = set()
    discovered_lazy_manifests: list[str] = []
    seen_lazy_manifests: set[str] = set()

    idx = 0
    for docs, prefix, default_ctype, is_js_batch in (
        (list(collector.captured_html.values()), "html", "text/html", False),
        (list(collector.captured_js.values())[:_MAX_JS_CHUNKS], "js", "application/javascript", True),
        (list(collector.captured_css.values())[:_MAX_CSS_DOCS], "css", "text/css", False),
    ):
        for doc in docs:
            idx += 1
            doc_url = str(doc.get("url") or "")
            doc_parts = _normalized_origin_parts(doc_url)
            is_cdn_doc = bool(
                doc.get("is_cdn")
                or (
                    doc_parts is not None
                    and base_origin_parts is not None
                    and doc_parts[:3] != base_origin_parts[:3]
                )
            )
            if is_js_batch:
                collector.js_chunks_parsed += 1
                if is_cdn_doc:
                    collector.cdn_js_chunks_parsed += 1
            doc_body = str(doc.get("body") or "")
            if canonical_hosts and doc_body:
                doc_body = rewrite_internal_canonical_urls_in_text(
                    doc_body,
                    base_url=http_client.base_url,
                    canonical_hosts=canonical_hosts,
                )
            if prefix == "html" and doc_body:
                _scan_document_for_external_api_hosts(
                    collector,
                    doc_body,
                    doc_url=doc_url,
                    is_js=False,
                )
                for sm in _INLINE_HTML_SCRIPT_RE.finditer(doc_body):
                    attrs, s_body = sm.group(1) or "", sm.group(2) or ""
                    if "src=" in attrs.lower() or not s_body.strip():
                        continue
                    _scan_document_for_external_api_hosts(
                        collector,
                        s_body,
                        doc_url=doc_url,
                        is_js=True,
                    )
            elif is_js_batch and doc_body:
                _scan_document_for_external_api_hosts(
                    collector,
                    doc_body,
                    doc_url=doc_url,
                    is_js=True,
                )

            if prefix in {"html", "js"} and doc_body:
                route_resolve_base = http_client.base_url if is_cdn_doc else (doc_url or http_client.base_url)
                lazy_info = _extract_lazy_spa_routes_and_chunks(
                    doc_body,
                    doc_url=route_resolve_base,
                    base_url=http_client.base_url,
                )
                for spa_r in lazy_info["routes"]:
                    collector.record_route(method="GET", raw_url=spa_r, current_url=route_resolve_base)
                if lazy_info["chunks"]:
                    collector.record_lazy_chunks(lazy_info["chunks"])
                for m_ref in lazy_info["manifests"]:
                    if m_ref not in seen_lazy_manifests and len(discovered_lazy_manifests) < 4:
                        seen_lazy_manifests.add(m_ref)
                        discovered_lazy_manifests.append(m_ref)

            if is_js_batch and doc_body:
                smap_refs = _extract_sourcemap_references(doc_body, doc_url)
                for inline_uri in smap_refs["inline"]:
                    _decode_and_ingest_sourcemap(
                        http_client,
                        collector,
                        inline_uri,
                        source_url=doc_url,
                        is_cdn=is_cdn_doc,
                        in_scope_assets=in_scope_assets,
                        out_of_scope_assets=out_of_scope_assets,
                        canonical_hosts=canonical_hosts,
                    )
                for ext_map_url in smap_refs["external"]:
                    if ext_map_url not in seen_external_sourcemaps and len(pending_external_sourcemaps) < 16:
                        seen_external_sourcemaps.add(ext_map_url)
                        pending_external_sourcemaps.append((ext_map_url, is_cdn_doc, doc_url))

            summary_doc_url = doc_url
            summary_source_url = doc_url
            summary_ctype = str(doc.get("content_type") or default_ctype)
            if is_js_batch and is_cdn_doc:
                # Resolve relative routes in CDN JS chunks against the target origin rather than CDN origin.
                doc_path = urlsplit(doc_url).path or "/cdn-bundle.js"
                summary_doc_url = urljoin(http_client.base_url, doc_path)
                summary_source_url = http_client.base_url
                if "javascript" not in summary_ctype.lower() and "ecmascript" not in summary_ctype.lower():
                    summary_ctype = "application/javascript"

            fake_rec = {
                "receipt_id": f"stage0-{prefix}-{idx}",
                "url": summary_doc_url,
                "content_type": summary_ctype,
                "body": doc_body,
                "response_headers": doc["headers"],
                "redirect_location": "",
            }
            try:
                summary = _extract_surface_summary(
                    fake_rec,
                    http_client.base_url,
                    in_scope_assets=in_scope_assets,
                    out_of_scope_assets=out_of_scope_assets,
                )
                collector.ingest_surface_summary(summary, source_url=summary_source_url)
            except Exception:
                continue

    for spec_url, parsed_spec in list(collector.captured_specs.values()):
        _ingest_openapi_spec(
            http_client,
            collector,
            parsed_spec,
            spec_url=spec_url,
        )

    if max_passive_probes <= 0 or "GET" not in http_client.allowed_methods:
        return

    # Bounded external .js.map fetch (up to _MAX_SOURCEMAPS_FETCHED = 4, 1 MiB each).
    if pending_external_sourcemaps and _parse_source_map is not None:
        sourcemaps_fetched = 0
        for ext_map_url, map_is_cdn, map_referrer_url in pending_external_sourcemaps:
            if sourcemaps_fetched >= _MAX_SOURCEMAPS_FETCHED:
                break
            in_scope_map_target = ""
            try:
                clean_m, _mp, _mq = _check_http_scope(http_client, ext_map_url, allow_fragment=False)
                in_scope_map_target = _scoped_storage_key(clean_m, http_client.base_url, include_query=True)
            except ScopeViolationError:
                in_scope_map_target = ""

            raw_map_text = ""
            if in_scope_map_target:
                if not stage0_budget.can_spend(include_reserve=True):
                    continue
                before_used = int(http_client.budget.used)
                try:
                    rec_m = http_client.request(actor=primary_actor, method="GET", url=in_scope_map_target)
                except BudgetExhaustedError:
                    stage0_budget.global_exhausted = True
                    break
                except ServiceDegradationError:
                    break
                except Exception:
                    after_used = int(http_client.budget.used)
                    stage0_budget.account_external(max(0, after_used - before_used))
                    continue
                after_used = int(http_client.budget.used)
                stage0_budget.account_external(max(0, after_used - before_used))
                sourcemaps_fetched += 1
                if 200 <= int(rec_m.get("status") or 0) < 300:
                    raw_map_text = str(rec_m.get("body") or "")[:_MAX_SOURCEMAP_BYTES]
            elif (
                not _is_explicitly_excluded_by_scope(scope_guard, ext_map_url)
                and _is_allowed_cdn_sourcemap_url(
                    ext_map_url,
                    http_client.base_url,
                    referrer_url=map_referrer_url,
                    scope_guard=scope_guard,
                    resolve_dns=True,
                    fail_closed_on_dns_error=True,
                )
            ):
                if not stage0_budget.can_spend(include_reserve=True):
                    break
                sourcemaps_fetched += 1
                raw_map_text = _fetch_cdn_sourcemap_anonymously(
                    http_client,
                    ext_map_url,
                    referrer_url=map_referrer_url,
                    stage0_budget=stage0_budget,
                )
                map_is_cdn = True
            else:
                continue

            if raw_map_text:
                _decode_and_ingest_sourcemap(
                    http_client,
                    collector,
                    raw_map_text,
                    source_url=ext_map_url,
                    is_cdn=map_is_cdn,
                    in_scope_assets=in_scope_assets,
                    out_of_scope_assets=out_of_scope_assets,
                    canonical_hosts=canonical_hosts,
                )

    detected_techs = detect_tech(
        server=" ".join(collector.server_headers),
        powered_by=" ".join(collector.powered_by_headers),
        body="\n".join(collector.body_snippets),
    )
    tech_probes: list[str] = []
    for tech in detected_techs:
        for tpath in _BENIGN_TECH_PROBES.get(tech, ()):
            if tpath not in tech_probes and len(tech_probes) < 3:
                tech_probes.append(tpath)

    seen_probes: set[str] = set()
    for raw_skip in skip_probe_paths or ():
        cand_skip = str(raw_skip or "").strip()
        if not cand_skip:
            continue
        try:
            clean_skip_u, _clean_skip_p, _q = _check_http_scope(http_client, cand_skip, allow_fragment=False)
            norm_skip = _scoped_storage_key(clean_skip_u, http_client.base_url)
        except (ScopeViolationError, ValueError):
            try:
                norm_skip = normalize_path(urlsplit(cand_skip).path or "/")
            except ValueError:
                continue
        seen_probes.add(norm_skip)

    found_openapi_spec = False
    stop_probing = False

    def _prepare_probe_candidates(raw_paths: Sequence[str]) -> list[str]:
        candidates: list[str] = []
        for raw_p in raw_paths:
            try:
                clean_u, clean_p, _q = _check_http_scope(http_client, raw_p, allow_fragment=False)
                norm_p = normalize_path(clean_p)
            except (ScopeViolationError, ValueError):
                continue
            low_p = norm_p.lower()
            if any(sens in low_p for sens in _SENSITIVE_PROBE_SEGMENTS):
                continue
            probe_target = _scoped_storage_key(clean_u, http_client.base_url)
            if probe_target in seen_probes or probe_target in collector.fetched_2xx_paths:
                continue
            seen_probes.add(probe_target)
            candidates.append(probe_target)
        return candidates

    def _execute_probe(probe_path: str, *, probe_cap: int | None = None) -> bool:
        nonlocal stop_probing
        if collector.passive_probes_sent >= max_passive_probes:
            stop_probing = True
            return False
        if probe_cap is not None and collector.passive_probes_sent >= probe_cap:
            return False
        if not stage0_budget.can_spend(include_reserve=True):
            stop_probing = True
            return False
        before_used = int(http_client.budget.used)
        try:
            rec = http_client.request(actor=primary_actor, method="GET", url=probe_path)
        except BudgetExhaustedError:
            stage0_budget.global_exhausted = True
            stop_probing = True
            return False
        except ServiceDegradationError:
            stop_probing = True
            return False
        except (ScopeViolationError, MethodNotAllowedError):
            return False
        except Exception:
            after_used = int(http_client.budget.used)
            stage0_budget.account_external(max(0, after_used - before_used))
            return False

        after_used = int(http_client.budget.used)
        stage0_budget.account_external(max(0, after_used - before_used))
        collector.passive_probes_sent += 1
        collector.probed_paths.add(probe_path)

        status = int(rec.get("status") or 0)
        rec_url = str(rec.get("url") or urljoin(http_client.base_url, probe_path))
        loc_hdr = str(rec.get("redirect_location") or "").strip()
        if loc_hdr and collector._allow_canonical_host_aliases:
            collector.register_canonical_hosts(
                detect_internal_canonical_hosts(
                    "",
                    base_url=http_client.base_url,
                    location_header=loc_hdr,
                )
            )
            collector.record_route(method="GET", raw_url=loc_hdr, current_url=rec_url)

        body_text = str(rec.get("body") or "")
        rec_ctype = str(rec.get("content_type") or "")
        rec_path_low = (urlsplit(rec_url).path or "").lower().rstrip("/")
        if rec_path_low.endswith("/graphql"):
            ctype_low = rec_ctype.lower()
            body_stripped = body_text.lstrip()
            body_low = body_stripped.lower()
            is_html_resp = (
                "text/html" in ctype_low
                or "application/xhtml" in ctype_low
                or body_low.startswith(("<!doctype", "<html", "<head", "<body"))
                or "<html" in body_low[:512]
            )
            is_json_ctype = (
                "application/json" in ctype_low
                or "+json" in ctype_low
                or "application/graphql" in ctype_low
            )
            parsed_gql_obj: dict[str, Any] | None = None
            if body_stripped.startswith("{"):
                try:
                    cand_obj = json.loads(body_stripped[:262144])
                    if isinstance(cand_obj, dict):
                        parsed_gql_obj = cand_obj
                except ValueError:
                    parsed_gql_obj = None
            has_gql_json_markers = bool(
                parsed_gql_obj is not None
                and (
                    "errors" in parsed_gql_obj
                    or "data" in parsed_gql_obj
                    or "__schema" in body_stripped[:65536]
                )
            )
            if is_html_resp:
                is_gql_hit = False
            elif 200 <= status < 300:
                is_gql_hit = bool(
                    has_gql_json_markers
                    or (is_json_ctype and (parsed_gql_obj is not None or "__schema" in body_low))
                )
            elif status in {400, 405, 415}:
                is_gql_hit = bool(
                    has_gql_json_markers
                    or (
                        is_json_ctype
                        and (
                            "graphql" in body_low
                            or '"errors"' in body_low
                            or '"data"' in body_low
                            or "__schema" in body_low
                            or "query" in body_low
                        )
                    )
                    or "graphql" in ctype_low
                )
            else:
                is_gql_hit = False
            if is_gql_hit:
                collector.record_route(
                    method="POST",
                    raw_url=rec_url,
                    params=("query", "variables", "operationName"),
                    status=status,
                )

        if not (200 <= status < 300):
            return False

        collector.record_route(method="GET", raw_url=rec_url, status=status)

        if rec_path_low.endswith("_buildmanifest.js") and body_text:
            lazy_m = _extract_lazy_spa_routes_and_chunks(
                body_text,
                doc_url=rec_url,
                base_url=http_client.base_url,
            )
            for spa_r in lazy_m["routes"]:
                collector.record_route(method="GET", raw_url=spa_r, current_url=rec_url)
            if lazy_m["chunks"]:
                collector.record_lazy_chunks(lazy_m["chunks"])
            return False

        parsed_spec = _parse_openapi_spec_document(
            body_text,
            content_type=rec_ctype,
            path=urlsplit(rec_url).path or probe_path,
        )

        if parsed_spec is not None:
            summary_rec: dict[str, Any] | None = None
            if body_text.lstrip().startswith("{"):
                summary_rec = rec
            _ingest_openapi_spec(
                http_client,
                collector,
                parsed_spec,
                spec_url=rec_url,
                summary_rec=summary_rec,
            )
            return True

        try:
            summary_rec_non_spec = rec
            cur_aliases = collector.canonical_hosts_snapshot()
            if cur_aliases and body_text:
                summary_rec_non_spec = dict(rec)
                summary_rec_non_spec["body"] = rewrite_internal_canonical_urls_in_text(
                    body_text,
                    base_url=http_client.base_url,
                    canonical_hosts=cur_aliases,
                )
            summary = _extract_surface_summary(
                summary_rec_non_spec,
                http_client.base_url,
                in_scope_assets=in_scope_assets,
                out_of_scope_assets=out_of_scope_assets,
            )
            collector.ingest_surface_summary(
                summary,
                source_url=rec_url,
            )
        except Exception:
            pass
        return False

    def _collect_in_scope_sibling_origins() -> list[str]:
        candidates: list[tuple[int, int, str]] = []
        seen_sib: set[str] = set()
        obs_counts: dict[str, int] = {}

        def _consider_origin(raw_u: str, obs_count: int = 0) -> None:
            parts = _normalized_origin_parts(raw_u)
            if parts is None:
                return
            if base_origin_parts is not None and parts[:3] == base_origin_parts[:3]:
                return
            _scheme, sib_host, _port, orig = parts
            if orig in seen_sib:
                obs_counts[orig] = max(obs_counts.get(orig, 0), obs_count)
                return
            first_label = sib_host.split(".", 1)[0] if "." in sib_host else sib_host
            if _parse_ip_literal(sib_host) is None and "." in sib_host and first_label in _STATIC_CDN_SUBDOMAIN_PREFIXES:
                return
            any_allowed = False
            for sp in _SIBLING_SPEC_PROBES:
                try:
                    _check_http_scope(http_client, f"{orig}{sp}", allow_fragment=False)
                    any_allowed = True
                    break
                except ScopeViolationError:
                    continue
            if not any_allowed:
                return
            seen_sib.add(orig)
            obs_counts[orig] = obs_count
            if first_label in _API_SUBDOMAIN_HINTS:
                api_rank = 0
            elif any(tok in first_label for tok in ("api", "bff", "graphql", "gateway")):
                api_rank = 1
            else:
                api_rank = 2
            candidates.append((api_rank, 0, orig))

        for host_row in collector.export_discovered_api_hosts():
            _consider_origin(
                str(host_row.get("origin") or ""),
                obs_count=int(host_row.get("observations") or 0),
            )
        for raw_sp in start_paths or ():
            _consider_origin(str(raw_sp or ""), obs_count=0)

        candidates.sort(key=lambda item: (item[0], -obs_counts.get(item[2], 0), item[2]))
        return [item[2] for item in candidates[:_MAX_SIBLING_SPEC_PROBE_ORIGINS]]

    in_scope_sibling_origins = _collect_in_scope_sibling_origins()
    avail_probe_slots = min(max_passive_probes, stage0_budget.remaining(include_reserve=True))
    sibling_probe_reserve = min(4, avail_probe_slots // 2) if in_scope_sibling_origins else 0
    primary_probe_limit = max(0, min(max_passive_probes, avail_probe_slots) - sibling_probe_reserve)

    for probe_path in _prepare_probe_candidates(collector.discovered_spec_urls):
        if collector.passive_probes_sent >= primary_probe_limit:
            break
        if _execute_probe(probe_path, probe_cap=primary_probe_limit):
            found_openapi_spec = True
        if stop_probing:
            return

    if not found_openapi_spec and collector.passive_probes_sent < primary_probe_limit:
        for probe_path in _prepare_probe_candidates(_ROOT_SPEC_PROBES):
            if collector.passive_probes_sent >= primary_probe_limit:
                break
            if _execute_probe(probe_path, probe_cap=primary_probe_limit):
                found_openapi_spec = True
                break
            if stop_probing:
                return

    if not found_openapi_spec and collector.passive_probes_sent < primary_probe_limit:
        for probe_path in _prepare_probe_candidates(_API_PREFIXED_SPEC_PROBES):
            if collector.passive_probes_sent >= primary_probe_limit:
                break
            if _execute_probe(probe_path, probe_cap=primary_probe_limit):
                found_openapi_spec = True
                break
            if stop_probing:
                return

    if collector.passive_probes_sent < primary_probe_limit:
        for probe_path in _prepare_probe_candidates([*_STANDARD_NON_SPEC_MANIFEST_PROBES, *tech_probes]):
            if collector.passive_probes_sent >= primary_probe_limit:
                break
            _execute_probe(probe_path, probe_cap=primary_probe_limit)
            if stop_probing:
                return

    # Optional Next.js _buildManifest.js probe (at most 1) if discovered via __NEXT_DATA__.
    for manifest_ref in discovered_lazy_manifests[:1]:
        if (
            stop_probing
            or collector.passive_probes_sent >= primary_probe_limit
            or not stage0_budget.can_spend(include_reserve=True)
        ):
            break
        if manifest_ref in collector.captured_js:
            continue
        for m_cand in _prepare_probe_candidates([manifest_ref]):
            _execute_probe(m_cand, probe_cap=primary_probe_limit)
            if stop_probing:
                return

    # Sibling-Origin Passive Spec & GraphQL Probes (up to 2 in-scope sibling API origins).
    if stop_probing or collector.passive_probes_sent >= max_passive_probes or not stage0_budget.can_spend(include_reserve=True):
        return

    in_scope_sibling_origins = _collect_in_scope_sibling_origins()

    for sib_orig in in_scope_sibling_origins:
        if stop_probing or collector.passive_probes_sent >= max_passive_probes or not stage0_budget.can_spend(include_reserve=True):
            break
        found_sib_spec = False
        for spec_path in _SIBLING_SPEC_PROBES:
            if stop_probing or collector.passive_probes_sent >= max_passive_probes or not stage0_budget.can_spend(include_reserve=True):
                break
            if found_sib_spec and spec_path in {"/swagger.json", "/v3/api-docs"}:
                continue
            full_sib_probe = f"{sib_orig}{spec_path}"
            for probe_cand in _prepare_probe_candidates([full_sib_probe]):
                if _execute_probe(probe_cand):
                    found_sib_spec = True
                if stop_probing:
                    return


def _finalize_routes(
    collector: _Stage0Collector,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, list[str]]],
    list[str],
]:
    """Cluster by ``(method, route_template)``, merge schemas, rank, and build seed lists."""
    clusters: dict[tuple[str, str], list[_RouteRecord]] = {}
    for rec in collector.routes.values():
        tmpl_path = route_template_of(rec.path)
        tmpl = f"{rec.origin}{tmpl_path}" if rec.origin else tmpl_path
        clusters.setdefault((rec.method, tmpl), []).append(rec)

    body_templates_map: dict[str, dict[str, Any]] = {}
    multipart_schemas_map: dict[str, dict[str, list[str]]] = {}
    clustered_items: list[tuple[int, int, str, str, dict[str, Any]]] = []

    for (method, tmpl), members in clusters.items():
        merged_params: set[str] = set()
        merged_mp_fields: set[str] = set()
        merged_mp_files: set[str] = set()
        best_template: dict[str, Any] | None = None
        best_template_observed = False
        cluster_is_form = False

        for rec in members:
            merged_params.update(rec.params)
            merged_params.update(_extract_path_embedded_params(rec.path))
            merged_mp_fields.update(rec.multipart_fields)
            merged_mp_files.update(rec.multipart_files)
            if rec.is_form:
                cluster_is_form = True
            if rec.body_template is not None:
                if (
                    best_template is None
                    or (rec.body_template_observed and not best_template_observed)
                    or (
                        rec.body_template_observed == best_template_observed
                        and len(rec.body_template) > len(best_template)
                    )
                ):
                    best_template = rec.body_template
                    best_template_observed = rec.body_template_observed

        sorted_params = sorted(merged_params)[:_MAX_PARAMS_PER_ROUTE]
        mp_schema: dict[str, list[str]] | None = None
        if merged_mp_fields or merged_mp_files:
            mp_schema = {
                "fields": sorted(merged_mp_fields)[:24],
                "files": sorted(merged_mp_files)[:16],
            }
            multipart_schemas_map[f"{method} {tmpl}"] = mp_schema
            cluster_is_form = True

        if best_template is not None:
            body_templates_map[f"{method} {tmpl}"] = best_template

        # Select up to _MAX_REPS_PER_CLUSTER representative concrete paths for this cluster.
        ranked_members = sorted(
            members,
            key=lambda r: (
                1 if "{" in r.path else 0,
                -_status_priority(r.best_status),
                0 if (r.params or r.body_template or r.multipart_files or r.is_form) else 1,
                r.first_seen,
                r.export_url,
            ),
        )
        for rep in ranked_members[:_MAX_REPS_PER_CLUSTER]:
            rep_url = rep.export_url
            entry: dict[str, Any] = {
                "method": method,
                "url": rep_url,
                "params": list(sorted_params),
                "status": int(rep.best_status),
            }
            if cluster_is_form:
                entry["is_form"] = True
            if best_template is not None:
                entry["body_template"] = best_template
            if mp_schema is not None:
                entry["multipart_schema"] = mp_schema

            score = _route_priority_score(
                method=method,
                path=rep.path,
                params=sorted_params,
                is_form=cluster_is_form,
                status=int(rep.best_status),
                has_body_template=best_template is not None,
                has_multipart_schema=mp_schema is not None,
            )
            clustered_items.append((-score, rep.first_seen, rep_url, method, entry))

    clustered_items.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
    seo_pattern_counts: dict[str, int] = {}
    kept_entries: list[dict[str, Any]] = []
    for _neg_score, _seen_ord, _rep_u, _meth, entry in clustered_items:
        seo_cls = _classify_seo_route_pattern(
            str(entry.get("url") or ""),
            method=str(entry.get("method") or "GET"),
            params=entry.get("params") or (),
            is_form=bool(entry.get("is_form")),
            has_body_template=bool(entry.get("body_template")),
            has_multipart_schema=bool(entry.get("multipart_schema")),
        )
        if seo_cls:
            cnt = seo_pattern_counts.get(seo_cls, 0)
            if cnt >= _MAX_SEO_ROUTES_PER_PATTERN:
                continue
            seo_pattern_counts[seo_cls] = cnt + 1
        kept_entries.append(entry)
        if len(kept_entries) >= _MAX_ROUTES_RETURNED:
            break

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    for entry in kept_entries:
        if entry.get("is_form"):
            forms.append(entry)
        else:
            links.append(entry)

    discovery_hints = _select_discovery_hints(kept_entries, _MAX_DISCOVERY_HINTS)
    return links, forms, body_templates_map, multipart_schemas_map, discovery_hints


def _normalize_stage0_seed_urls(
    http_client: AgenticHTTPClient,
    raw_paths: Sequence[str] | None,
    *,
    seen_keys: set[tuple[str, str, str]] | None = None,
    block_destructive: bool = False,
) -> list[str]:
    """Normalize, scope-check, filter, and deduplicate Stage 0 crawl entry URLs."""
    if not raw_paths:
        return []
    dedup_keys = seen_keys if seen_keys is not None else set()
    accepted: list[str] = []
    for raw_sp in raw_paths:
        cand = str(raw_sp or "").strip()
        if not cand or "<REDACTED" in cand:
            continue
        low = cand.lower()
        if low.startswith(_NON_HTTP_SCHEMES) or low.startswith(("ws://", "wss://")):
            continue
        try:
            full_s, path_u, query_u = _check_http_scope(http_client, cand, allow_fragment=True)
            norm_p = normalize_path(path_u or "/")
        except (ScopeViolationError, ValueError):
            continue
        if (
            has_double_slash_path(path_u)
            or (is_static_asset_url(norm_p) and not _extract_path_embedded_params(norm_p))
            or is_non_endpoint_source_path(norm_p)
            or _is_stage0_noise_path(norm_p, origin_url=http_client.base_url)
            or norm_p.lower().endswith(_SCRIPT_ASSET_EXTS)
            or is_logout_route(norm_p)
            or is_destructive_lifecycle_route(norm_p)
        ):
            continue
        if block_destructive and _DESTRUCTIVE_RE.search(norm_p):
            continue
        frag = urlsplit(full_s).fragment
        scoped_p = _scoped_storage_key(full_s, http_client.base_url)
        canon_key = (scoped_p, query_u, frag)
        if canon_key in dedup_keys:
            continue
        dedup_keys.add(canon_key)
        accepted.append(full_s)
    return accepted


def run_stage0_crawl(
    http_client: AgenticHTTPClient,
    *,
    output_dir: Path | str | None = None,
    start_paths: Sequence[str] | None = None,
    extra_seed_paths: Sequence[str] | None = None,
    max_pages: int = 12,
    max_actions: int = 24,
    allow_forms: bool = False,
    actors: Sequence[str] | None = None,
    seed_filename: str = "stage0-seed.json",
    timeout_ms: int = 12000,
    wait_ms: int = 500,
    max_passive_probes: int = 12,
    skip_probe_paths: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Run deterministic Stage 0 Playwright surface crawl and return ``stage0-seed/1`` payload."""
    started = time.monotonic()

    if not HAS_PLAYWRIGHT or _sync_playwright is None:
        return _empty_result(
            http_client.base_url,
            status="skipped_no_playwright",
            mode="readonly",
            elapsed_seconds=time.monotonic() - started,
        )

    forms_enabled = bool(allow_forms and ("POST" in http_client.allowed_methods))
    mode = "forms" if forms_enabled else "readonly"

    eff_max_pages = max(1, min(int(max_pages), 60))
    eff_max_actions = max(0, min(int(max_actions), 120))
    eff_max_probes = max(0, min(int(max_passive_probes), 40))
    eff_timeout_ms = max(1000, min(int(timeout_ms), 30000))
    eff_wait_ms = max(0, min(int(wait_ms), 3000))

    remaining = _budget_remaining(http_client)
    if remaining <= 0:
        return _empty_result(
            http_client.base_url,
            status="budget_exhausted",
            mode=mode,
            elapsed_seconds=time.monotonic() - started,
        )

    stage0_cap = min(
        remaining,
        max(
            12,
            min(
                remaining // 3,
                eff_max_pages * 3 + eff_max_actions + eff_max_probes,
                64,
            ),
        ),
    )
    passive_reserve = 0
    if eff_max_probes > 0 and "GET" in http_client.allowed_methods and stage0_cap > 1:
        is_multi_orig = bool(getattr(getattr(http_client, "scope_guard", None), "is_multi_origin", False))
        if is_multi_orig:
            passive_reserve = min(eff_max_probes, max(4, stage0_cap // 4), 12, stage0_cap - 1)
        else:
            passive_reserve = min(eff_max_probes, max(1, stage0_cap // 5), 8, stage0_cap - 1)
    stage0_budget = _Stage0Budget(http_client, cap=stage0_cap, reserve=passive_reserve)

    if actors is not None and len(actors) > 0:
        actor_map = getattr(http_client.actors, "actors", {}) or {}
        selected_actors: list[str] = []
        for raw_a in actors:
            alias = str(raw_a or "").strip()
            if alias and alias in actor_map and alias not in selected_actors:
                selected_actors.append(alias)
        if not selected_actors:
            return _empty_result(
                http_client.base_url,
                status="ok",
                mode=mode,
                actors_crawled=(),
                elapsed_seconds=time.monotonic() - started,
            )
    else:
        selected_actors = _select_crawl_actors(http_client, None)
    seen_seed_keys: set[tuple[str, str, str]] = set()
    raw_starts = list(start_paths) if start_paths else ["/"]
    valid_starts = _normalize_stage0_seed_urls(
        http_client,
        raw_starts,
        seen_keys=seen_seed_keys,
        block_destructive=False,
    )
    if not valid_starts:
        valid_starts = _normalize_stage0_seed_urls(
            http_client,
            ["/"],
            seen_keys=seen_seed_keys,
            block_destructive=False,
        )
    if extra_seed_paths:
        valid_starts.extend(
            _normalize_stage0_seed_urls(
                http_client,
                extra_seed_paths,
                seen_keys=seen_seed_keys,
                block_destructive=True,
            )
        )
    if not valid_starts:
        return _empty_result(
            http_client.base_url,
            status="ok",
            mode=mode,
            actors_crawled=selected_actors,
            elapsed_seconds=time.monotonic() - started,
        )

    collector = _Stage0Collector(http_client)
    collected_secrets: set[str] = set()
    all_secrets_fn = getattr(http_client.actors, "all_secrets", None)
    if callable(all_secrets_fn):
        for s in all_secrets_fn() or ():
            sval = str(s or "")
            if len(sval) >= 4:
                collected_secrets.add(sval)

    def _run_playwright_stage() -> dict[str, Any]:
        assert _sync_playwright is not None
        actors_done: list[str] = []
        with _sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
            anon_req_ctx: Any = None
            req_api = getattr(playwright, "request", None)
            if req_api is not None and callable(getattr(req_api, "new_context", None)):
                try:
                    anon_req_ctx = req_api.new_context(ignore_https_errors=True)
                except Exception:
                    anon_req_ctx = None
            try:
                total_actors = len(selected_actors)
                for idx, actor_alias in enumerate(selected_actors):
                    if collector.pages_visited >= eff_max_pages or not stage0_budget.can_spend():
                        break
                    rem_after = total_actors - idx - 1
                    reserve_pages = (
                        rem_after * max(1, eff_max_pages // total_actors)
                        if eff_max_pages >= total_actors
                        else 0
                    )
                    actor_pages = max(1, (eff_max_pages - collector.pages_visited) - reserve_pages)
                    reserve_actions = (
                        rem_after * max(1, eff_max_actions // total_actors)
                        if eff_max_actions >= total_actors
                        else 0
                    )
                    actor_actions = max(0, (eff_max_actions - collector.ui_actions_taken) - reserve_actions)

                    secrets_for_actor = _crawl_actor_playwright(
                        http_client,
                        collector,
                        stage0_budget,
                        browser=browser,
                        actor=actor_alias,
                        start_urls=valid_starts,
                        forms_enabled=forms_enabled,
                        actor_page_limit=actor_pages,
                        actor_action_limit=actor_actions,
                        timeout_ms=eff_timeout_ms,
                        wait_ms=eff_wait_ms,
                        anon_request_context=anon_req_ctx,
                    )
                    collected_secrets.update(secrets_for_actor)
                    actors_done.append(actor_alias)
            finally:
                if anon_req_ctx is not None:
                    try:
                        anon_req_ctx.dispose()
                    except Exception:
                        pass
                try:
                    browser.close()
                except Exception:
                    pass
        return {"actors_crawled": actors_done}

    crawl_error = ""
    actors_crawled: list[str] = []
    try:
        pw_timeout = max(45.0, (eff_timeout_ms / 1000.0) * max(3, eff_max_pages) + 20.0)
        pw_res = _run_sync(_run_playwright_stage, timeout=pw_timeout)
        if isinstance(pw_res, dict) and isinstance(pw_res.get("actors_crawled"), list):
            actors_crawled = [str(a) for a in pw_res["actors_crawled"]]
    except Exception as exc:
        crawl_error = f"{type(exc).__name__}: {str(exc)[:200]}"

    primary_actor = actors_crawled[0] if actors_crawled else selected_actors[0]
    if not crawl_error:
        _run_layer4_passive_fusion(
            http_client,
            collector,
            stage0_budget,
            primary_actor=primary_actor,
            max_passive_probes=eff_max_probes,
            skip_probe_paths=skip_probe_paths,
            start_paths=valid_starts,
        )

    links, forms, body_templates_map, multipart_schemas_map, discovery_hints = _finalize_routes(collector)
    ws_endpoints = list(collector.ws_endpoints.values())
    discovered_api_hosts = collector.export_discovered_api_hosts()
    probed_paths_sorted = sorted(collector.probed_paths)
    auth_headers_list = list(collector.discovered_auth_headers)
    observed_app_headers = dict(sorted(collector.observed_app_headers.items()))
    elapsed = round(time.monotonic() - started, 3)

    if crawl_error and not links and not forms and not ws_endpoints:
        final_status = "error"
    elif stage0_budget.global_exhausted and collector.pages_visited == 0 and not links and not forms:
        final_status = "budget_exhausted"
    else:
        final_status = "ok"

    stats: dict[str, Any] = {
        "status": final_status,
        "mode": mode,
        "actors_crawled": list(actors_crawled),
        "pages_visited": int(collector.pages_visited),
        "dom_states_seen": int(collector.dom_states_seen),
        "ui_actions_taken": int(collector.ui_actions_taken),
        "forms_submitted": int(collector.forms_submitted),
        "uploads_triggered": int(collector.uploads_triggered),
        "network_requests_captured": int(collector.network_requests_captured),
        "js_chunks_parsed": int(collector.js_chunks_parsed),
        "cdn_js_chunks_parsed": int(collector.cdn_js_chunks_parsed),
        "source_maps_parsed": int(collector.source_maps_parsed),
        "lazy_chunks_discovered": int(collector.lazy_chunks_discovered),
        "passive_probes_sent": int(collector.passive_probes_sent),
        "probed_paths": probed_paths_sorted,
        "discovered_auth_headers": list(auth_headers_list),
        "external_api_hosts_seen": len(discovered_api_hosts),
        "ws_endpoints_found": len(ws_endpoints),
        "routes_accepted": len(links) + len(forms),
        "body_templates_count": len(body_templates_map),
        "multipart_schemas_count": len(multipart_schemas_map),
        "requests_charged": int(stage0_budget.charged),
        "elapsed_seconds": elapsed,
    }
    if crawl_error:
        stats["error"] = crawl_error

    result: dict[str, Any] = {
        "schema": "stage0-seed/1",
        "url": http_client.base_url,
        "status": final_status,
        "mode": mode,
        "actors_crawled": list(actors_crawled),
        "links": links,
        "forms": forms,
        "ws_endpoints": ws_endpoints,
        "body_templates": body_templates_map,
        "multipart_schemas": multipart_schemas_map,
        "auth_headers": auth_headers_list,
        "observed_app_headers": observed_app_headers,
        "discovered_api_hosts": discovered_api_hosts,
        "discovery_hints": discovery_hints,
        "seed_file": "",
        "stats": stats,
    }

    sorted_secrets = sorted(collected_secrets, key=len, reverse=True)
    redacted_result: dict[str, Any] = _redact_recursive(result, sorted_secrets)

    if output_dir is not None:
        safe_seed_name = Path(str(seed_filename or "stage0-seed.json")).name or "stage0-seed.json"
        seed_path = Path(output_dir) / safe_seed_name
        redacted_result["seed_file"] = str(seed_path)
        _write_json_atomic(seed_path, redacted_result)

    return redacted_result


__all__ = [
    "HAS_PLAYWRIGHT",
    "extract_openapi_header_auth_names",
    "run_stage0_crawl",
    "should_skip_stage0_form_submit",
]
