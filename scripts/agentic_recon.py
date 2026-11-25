#!/usr/bin/env python3
"""Scope-locked pre-assessment recon, passive CT discovery, and AssetGraph builder (Faz A)."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from html import unescape as html_unescape
import inspect
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Sequence
from urllib.parse import quote, urljoin, urlsplit
import urllib.request
import uuid

import requests

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

_REPO_ROOT = _SCRIPTS_DIR.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agentic_http import (  # noqa: E402
    DEFAULT_BROWSER_USER_AGENT,
    is_static_asset_url,
    normalize_global_headers,
    parse_custom_headers,
)
from agentic_waf import detect_waf_block  # noqa: E402
from target_bootstrap import (  # noqa: E402
    ScopeGuard,
    _default_port,
    _is_valid_host,
    _parse_scope_asset,
    load_scope_file,
    normalize_path,
    resolve_target_origin,
)
from tech_routes import detect_tech  # noqa: E402
from wire_budget import WireBudget  # noqa: E402

SCHEMA = "cco-asset-graph/1"
PLAN_SCHEMA = "cco-recon-plan/1"
SCOPE_RECOMMENDED_SCHEMA = "cco-scope-recommended/1"

MAX_SEED_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_CT_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_PROBE_BODY_BYTES = 512 * 1024  # 512 KiB
MAX_SAMPLE_PATHS = 20
MAX_TITLE_CHARS = 120
MAX_META_CHARS = 160

VALID_ROLES = frozenset({
    "api",
    "auth",
    "storefront",
    "admin",
    "graphql",
    "cdn",
    "unknown",
})

ROLE_PRIORITY: dict[str, int] = {
    "api": 0,
    "graphql": 1,
    "auth": 2,
    "admin": 3,
    "unknown": 4,
    "storefront": 5,
    "cdn": 6,
}

_EDGE_RELATIONS = frozenset({
    "calls_api",
    "authenticates_at",
    "loads_cdn_js",
    "redirects_to",
})

_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
_VALID_SCHEMES = frozenset({"http", "https"})

_API_HOST_LABELS = frozenset({
    "api",
    "bff",
    "sfapi",
    "rest",
    "rpc",
    "gateway",
    "gw",
    "backend",
    "service",
    "services",
    "edge-api",
})
_AUTH_HOST_LABELS = frozenset({
    "auth",
    "oauth",
    "oauth2",
    "sso",
    "login",
    "signin",
    "idp",
    "identity",
    "keycloak",
    "accounts",
})
_ADMIN_HOST_LABELS = frozenset({
    "admin",
    "backoffice",
    "panel",
    "console",
    "internal",
    "manage",
    "mgmt",
    "staff",
    "ops",
})
_GRAPHQL_HOST_LABELS = frozenset({"graphql", "gql"})
_CDN_HOST_LABELS = frozenset({
    "cdn",
    "static",
    "assets",
    "asset",
    "img",
    "images",
    "image",
    "media",
    "js",
    "css",
    "font",
    "fonts",
    "files",
})
_STOREFRONT_HOST_LABELS = frozenset({"www", "shop", "store", "web", "m", "catalog"})

_API_PATH_RE = re.compile(
    r"^/(?:(?:ajax[-_]?)?api(?:/v\d+(?:\.\d+)?)?|v\d+(?:\.\d+)?|rest|rpc|openapi(?:\.json)?|swagger(?:\.json|-ui)?|v3/api-docs)(?:/|$)",
    re.IGNORECASE,
)
_GRAPHQL_PATH_RE = re.compile(r"^/(?:api/)?(?:v\d+/)?(?:graphql|graphiql|gql)(?:/|$)", re.IGNORECASE)
_AUTH_PATH_RE = re.compile(
    r"^/(?:\.well-known/openid-configuration|oauth\d?/|oidc/|sso/|saml/|auth(?:/|$)|login(?:/|$)|signin(?:/|$))",
    re.IGNORECASE,
)
_ADMIN_PATH_RE = re.compile(r"^/(?:admin|backoffice|console|mgmt)(?:/|$)", re.IGNORECASE)
_SCRIPT_EXT_RE = re.compile(r"\.(?:js|mjs|cjs|css|map)(?:\?|$)", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_PASSWORD_INPUT_RE = re.compile(r"""<input\b[^>]*\btype\s*=\s*["']?password\b""", re.IGNORECASE)
_ABS_URL_RE = re.compile(r"https?://[^\s\"'<>`\\)}\]]+", re.IGNORECASE)
_SAFE_ROBOTS_PATH_RE = re.compile(r"^/[A-Za-z0-9._~:/?#\[\]@!$&'()+;,=%-]{1,160}$")

_MULTI_LABEL_CC_SLDS = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "mil", "ne", "or"})

_THIRD_PARTY_TRACKER_DOMAINS = frozenset({
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "googlesyndication.com",
    "googleadservices.com",
    "doubleclick.net",
    "connect.facebook.net",
    "facebook.com",
    "facebook.net",
    "hotjar.com",
    "clarity.ms",
    "mixpanel.com",
    "segment.com",
    "segment.io",
    "amplitude.com",
    "sentry.io",
    "sentry-cdn.com",
    "datadoghq.com",
    "newrelic.com",
    "nr-data.net",
    "tiktok.com",
    "criteo.com",
    "criteo.net",
    "useinsider.com",
    "onesignal.com",
    "recaptcha.net",
    "hcaptcha.com",
    "cloudflareinsights.com",
    "onetrust.com",
    "cookiebot.com",
})

_NON_SECRET_RESPONSE_HEADERS = frozenset({
    "content-type",
    "server",
    "x-powered-by",
    "location",
    "www-authenticate",
    "cf-ray",
    "cf-mitigated",
    "cf-error-details",
    "x-amzn-waf",
    "x-wa-info",
    "x-sucuri-id",
    "x-cdn",
    "x-iinfo",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-vercel-id",
    "x-nextjs-cache",
    "x-nextjs-matched-path",
    "x-generator",
    "retry-after",
})


def _sanitize_single_line(raw: Any, *, max_len: int = MAX_META_CHARS) -> str:
    text = re.sub(r"[\r\n\t\x00-\x1f\x7f]+", " ", str(raw or "")).strip()
    text = re.sub(r"\s{2,}", " ", text)
    return text[:max_len]


def _format_origin(scheme: str, host: str, port: int) -> str:
    host_netloc = f"[{host}]" if ":" in host else host
    if port == _default_port(scheme):
        return f"{scheme}://{host_netloc}"
    return f"{scheme}://{host_netloc}:{port}"


def _parse_origin_parts(
    raw_url: str,
    *,
    default_scheme: str = "https",
) -> tuple[str, str, str, int, str] | None:
    """Parse URL or bare host[:port] into ``(origin, scheme, host, port, path)`` or None."""
    raw = str(raw_url or "").strip()
    if not raw or raw.startswith(("/", "//", "#")):
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        return None
    if "*" in raw:
        return None

    candidate = raw
    if "://" not in candidate:
        scheme_guess = default_scheme if default_scheme in _VALID_SCHEMES else "https"
        candidate = f"{scheme_guess}://{candidate}"

    try:
        parsed = urlsplit(candidate)
        port_val = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in _VALID_SCHEMES:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None

    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host or not _is_valid_host(host):
        return None
    if port_val is not None and not (1 <= port_val <= 65535):
        return None

    eff_port = port_val if port_val is not None else _default_port(scheme)
    origin = _format_origin(scheme, host, eff_port)
    try:
        norm_p = normalize_path(parsed.path or "/")
    except ValueError:
        norm_p = "/"
    return origin, scheme, host, eff_port, norm_p


def _is_tracker_host(host: str) -> bool:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean:
        return False
    return any(clean == dom or clean.endswith("." + dom) for dom in _THIRD_PARTY_TRACKER_DOMAINS)


def _is_loopback_or_private_host(host: str) -> bool:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean:
        return True
    if clean == "localhost" or clean.endswith((".localhost", ".local", ".internal")) or "." not in clean:
        return True
    try:
        ip = ipaddress.ip_address(clean)
        return bool(ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def _registrable_domain(host: str) -> str:
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


def _coerce_status(raw: Any) -> int | None:
    if isinstance(raw, bool) or raw is None:
        return None
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return None
    return val if 100 <= val <= 599 else None


def _host_labels_before_apex(host: str) -> list[str]:
    clean = str(host or "").strip().lower().rstrip(".")
    if not clean or ":" in clean:
        return []
    try:
        ipaddress.ip_address(clean)
        return []
    except ValueError:
        pass
    apex = _registrable_domain(clean)
    if clean == apex:
        return []
    if clean.endswith("." + apex):
        prefix = clean[: -(len(apex) + 1)]
        return [tok for part in prefix.split(".") for tok in part.split("-") if tok]
    return [tok for part in clean.split(".")[:-2] for tok in part.split("-") if tok]


def _infer_host_role(host: str, sample_paths: Sequence[str] = ()) -> str:
    labels = _host_labels_before_apex(host)
    label_set = set(labels)
    if label_set & _GRAPHQL_HOST_LABELS:
        return "graphql"
    if label_set & _AUTH_HOST_LABELS:
        return "auth"
    if label_set & _ADMIN_HOST_LABELS:
        return "admin"
    if label_set & _API_HOST_LABELS:
        return "api"
    if label_set & _CDN_HOST_LABELS:
        return "cdn"

    if any(_GRAPHQL_PATH_RE.match(p) for p in sample_paths):
        return "graphql"
    if any(_API_PATH_RE.match(p) for p in sample_paths):
        return "api"
    if any(_AUTH_PATH_RE.match(p) for p in sample_paths):
        return "auth"
    if any(_ADMIN_PATH_RE.match(p) for p in sample_paths):
        return "admin"
    if sample_paths and all(_SCRIPT_EXT_RE.search(p) or is_static_asset_url(p) for p in sample_paths if p != "/"):
        if any(p != "/" for p in sample_paths):
            return "cdn"
    if label_set & _STOREFRONT_HOST_LABELS:
        return "storefront"
    return "unknown"


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_path, path)


def _read_regular_file(path: Path | str, *, max_bytes: int = MAX_SEED_FILE_BYTES) -> str:
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
    return raw_bytes.decode("utf-8", errors="replace").lstrip("\ufeff")


def _merge_header_maps(*maps: dict[str, str] | None) -> dict[str, str]:
    merged: dict[str, str] = {}
    for mapping in maps:
        for hk, hv in (mapping or {}).items():
            for existing in [ek for ek in merged if ek.lower() == hk.lower()]:
                merged.pop(existing, None)
            merged[hk] = hv
    return normalize_global_headers(merged)


def _extract_title(html_text: str) -> str:
    if not html_text:
        return ""
    m = _TITLE_RE.search(html_text[:65536])
    if not m:
        return ""
    cleaned = html_unescape(m.group(1))
    return _sanitize_single_line(cleaned, max_len=MAX_TITLE_CHARS)


def _extract_response_signals(
    *,
    host: str,
    status: int | None,
    headers: dict[str, str],
    body: str,
    sample_paths: Sequence[str] = (),
) -> dict[str, Any]:
    """Extract non-secret tech signals, WAF classification, title, and host role from HTTP metadata."""
    low_headers = {str(k).strip().lower(): str(v).strip() for k, v in (headers or {}).items() if str(k).strip()}
    server = _sanitize_single_line(low_headers.get("server", ""), max_len=MAX_META_CHARS)
    powered_by = _sanitize_single_line(low_headers.get("x-powered-by", ""), max_len=MAX_META_CHARS)
    content_type = low_headers.get("content-type", "").split(";", 1)[0].strip().lower()
    location = low_headers.get("location", "").strip()

    tech_signals: set[str] = set()
    for tech in detect_tech(server=server, powered_by=powered_by, body=body[:20000]):
        tech_signals.add(tech)

    if "cf-ray" in low_headers:
        tech_signals.add("cloudflare")
    if "x-amz-cf-id" in low_headers or "x-amz-cf-pop" in low_headers:
        tech_signals.add("cloudfront")
    if "x-vercel-id" in low_headers:
        tech_signals.add("vercel")
    if "x-nextjs-cache" in low_headers or "x-nextjs-matched-path" in low_headers:
        tech_signals.add("nextjs")
    if "www-authenticate" in low_headers:
        tech_signals.add("auth_header")

    body_slice = (body or "")[:262144]
    body_low = body_slice.lower()
    stripped = body_slice.lstrip()

    is_json_ct = "json" in content_type or content_type == "application/problem+json"
    is_html_ct = "html" in content_type or stripped.lower().startswith(("<!doctype html", "<html"))
    parsed_json: Any = None
    if is_json_ct or stripped.startswith(("{", "[")):
        try:
            parsed_json = json.loads(body_slice)
            tech_signals.add("json")
        except ValueError:
            parsed_json = None

    if is_html_ct:
        tech_signals.add("html")

    if "__next_data__" in body_low or "/_next/static" in body_low:
        tech_signals.add("nextjs")
    if "__nuxt__" in body_low or "/_nuxt/" in body_low:
        tech_signals.add("nuxt")

    has_openapi_hint = False
    if isinstance(parsed_json, dict) and (
        ("openapi" in parsed_json or "swagger" in parsed_json) and "paths" in parsed_json
    ):
        has_openapi_hint = True
    elif any(tok in body_low for tok in ("swagger-ui", "swaggerui", "\"openapi\"", "\"swagger\"", "/v3/api-docs")):
        has_openapi_hint = True
    if has_openapi_hint:
        tech_signals.add("openapi")

    has_graphql_hint = False
    if isinstance(parsed_json, dict) and (
        "__schema" in parsed_json
        or ("data" in parsed_json and "errors" in parsed_json and "graphql" in body_low)
    ):
        has_graphql_hint = True
    elif any(tok in body_low for tok in ("graphiql", "graphql playground", "apollo-server", "\"__schema\"")):
        has_graphql_hint = True
    if has_graphql_hint:
        tech_signals.add("graphql")

    has_oidc_discovery = isinstance(parsed_json, dict) and (
        "authorization_endpoint" in parsed_json or "token_endpoint" in parsed_json or "jwks_uri" in parsed_json
    )
    has_login_form = bool(_PASSWORD_INPUT_RE.search(body_slice))
    if has_oidc_discovery or has_login_form or (location and _AUTH_PATH_RE.match(urlsplit(location).path or "/")):
        tech_signals.add("auth_hint")

    waf_vendor = ""
    if status is not None:
        waf_res = detect_waf_block({
            "status": status,
            "response_headers": headers,
            "body": body_slice,
            "content_type": content_type,
        })
        if isinstance(waf_res, dict) and waf_res.get("waf_blocked"):
            waf_vendor = _sanitize_single_line(waf_res.get("vendor") or "generic", max_len=64)
            tech_signals.add(f"waf:{waf_vendor}")

    title = _extract_title(body_slice) if is_html_ct else ""
    title_low = title.lower()

    host_role = _infer_host_role(host, sample_paths)
    inferred_role = host_role
    if has_graphql_hint:
        inferred_role = "graphql"
    elif has_oidc_discovery:
        inferred_role = "auth"
    elif host_role in {"api", "graphql", "auth", "admin", "cdn"}:
        inferred_role = host_role
    elif has_openapi_hint or is_json_ct or isinstance(parsed_json, (dict, list)):
        inferred_role = "api"
    elif is_html_ct:
        if any(tok in title_low for tok in ("admin", "administration", "dashboard console")):
            inferred_role = "admin"
        elif has_login_form and any(tok in title_low for tok in ("sign in", "log in", "login", "sso", "oauth", "authenticate")):
            inferred_role = "auth"
        else:
            inferred_role = "storefront"

    return {
        "role": inferred_role,
        "title": title,
        "server": server,
        "powered_by": powered_by,
        "waf_vendor": waf_vendor,
        "tech_signals": sorted(tech_signals),
    }


@dataclass
class AssetNode:
    """Strictly non-secret metadata describing a discovered host/origin in the AssetGraph."""

    origin: str
    scheme: str
    host: str
    port: int
    in_scope: bool = False
    role: str = "unknown"
    alive: bool | None = None
    status: int | None = None
    title: str = ""
    server: str = ""
    powered_by: str = ""
    waf_vendor: str = ""
    tech_signals: list[str] = field(default_factory=list)
    sample_paths: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.role not in VALID_ROLES:
            self.role = "unknown"
        self.title = _sanitize_single_line(self.title, max_len=MAX_TITLE_CHARS)
        self.server = _sanitize_single_line(self.server, max_len=MAX_META_CHARS)
        self.powered_by = _sanitize_single_line(self.powered_by, max_len=MAX_META_CHARS)
        self.waf_vendor = _sanitize_single_line(self.waf_vendor, max_len=64)
        self.tech_signals = sorted({str(t).strip() for t in self.tech_signals if str(t).strip()})
        self.sources = sorted({str(s).strip() for s in self.sources if str(s).strip()})
        self.sample_paths = _normalize_sample_paths(self.sample_paths)

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "scheme": self.scheme,
            "host": self.host,
            "port": int(self.port),
            "in_scope": bool(self.in_scope),
            "role": self.role,
            "alive": self.alive,
            "status": self.status,
            "title": self.title,
            "server": self.server,
            "powered_by": self.powered_by,
            "waf_vendor": self.waf_vendor,
            "tech_signals": sorted(self.tech_signals),
            "sample_paths": list(self.sample_paths),
            "sources": sorted(self.sources),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetNode:
        origin = str(data.get("origin") or "").strip()
        scheme = str(data.get("scheme") or "").strip().lower()
        host = str(data.get("host") or "").strip().lower().rstrip(".")
        port_raw = data.get("port")
        parsed = _parse_origin_parts(origin)
        if parsed is not None:
            origin, parsed_scheme, parsed_host, parsed_port, _ = parsed
            scheme = scheme or parsed_scheme
            host = host or parsed_host
            port = int(port_raw) if isinstance(port_raw, int) and not isinstance(port_raw, bool) and port_raw > 0 else parsed_port
        else:
            port = int(port_raw) if isinstance(port_raw, int) and not isinstance(port_raw, bool) and port_raw > 0 else _default_port(scheme or "https")
        alive_raw = data.get("alive")
        alive = alive_raw if isinstance(alive_raw, bool) else None
        status = _coerce_status(data.get("status"))
        role = str(data.get("role") or "unknown").strip().lower()
        if role not in VALID_ROLES:
            role = "unknown"
        return cls(
            origin=origin,
            scheme=scheme,
            host=host,
            port=port,
            in_scope=bool(data.get("in_scope", False)),
            role=role,
            alive=alive,
            status=status,
            title=str(data.get("title") or ""),
            server=str(data.get("server") or ""),
            powered_by=str(data.get("powered_by") or ""),
            waf_vendor=str(data.get("waf_vendor") or ""),
            tech_signals=[str(x) for x in (data.get("tech_signals") or []) if str(x).strip()],
            sample_paths=[str(x) for x in (data.get("sample_paths") or []) if str(x).strip()],
            sources=[str(x) for x in (data.get("sources") or []) if str(x).strip()],
        )


def _normalize_sample_paths(raw_paths: Sequence[str]) -> list[str]:
    concrete: list[str] = []
    has_root = False
    seen: set[str] = set()
    for raw in raw_paths:
        text = str(raw or "").strip()
        if not text:
            continue
        parsed_path = urlsplit(text).path if ("://" in text or "?" in text or "#" in text) else text
        try:
            norm = normalize_path(parsed_path or "/")
        except ValueError:
            continue
        if norm == "/":
            has_root = True
            continue
        if norm not in seen:
            seen.add(norm)
            concrete.append(norm)
            if len(concrete) >= MAX_SAMPLE_PATHS:
                return concrete
    if has_root and len(concrete) < MAX_SAMPLE_PATHS:
        concrete.append("/")
    return concrete[:MAX_SAMPLE_PATHS]


@dataclass
class AssetEdge:
    """Directed relationship between two origins in the AssetGraph."""

    source: str
    target: str
    relation: str
    evidence: str = ""
    sources: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.relation = _sanitize_single_line(self.relation, max_len=48).lower().replace(" ", "_") or "references"
        self.evidence = _sanitize_single_line(self.evidence, max_len=160)
        self.sources = sorted({str(s).strip() for s in self.sources if str(s).strip()})

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "evidence": self.evidence,
            "sources": sorted(self.sources),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetEdge:
        return cls(
            source=str(data.get("source") or "").strip().rstrip("/"),
            target=str(data.get("target") or "").strip().rstrip("/"),
            relation=str(data.get("relation") or "references").strip(),
            evidence=str(data.get("evidence") or ""),
            sources=[str(x) for x in (data.get("sources") or []) if str(x).strip()],
        )


class AssetGraph:
    """Scope-guarded multi-origin Asset Graph (schema ``cco-asset-graph/1``)."""

    def __init__(
        self,
        guard: ScopeGuard | None = None,
        *,
        base_origin: str = "",
    ) -> None:
        if guard is None and base_origin:
            guard = ScopeGuard(base_origin)
        self.guard: ScopeGuard | None = guard
        if guard is not None:
            parsed = _parse_origin_parts(guard.base_origin)
            self.base_origin = parsed[0] if parsed is not None else guard.base_origin.rstrip("/")
            self._default_scheme = parsed[1] if parsed is not None else "https"
        else:
            parsed = _parse_origin_parts(base_origin) if base_origin else None
            self.base_origin = parsed[0] if parsed is not None else ""
            self._default_scheme = parsed[1] if parsed is not None else "https"

        self.nodes: dict[str, AssetNode] = {}
        self.edges: dict[tuple[str, str, str], AssetEdge] = {}
        self.rejected_origins: set[str] = set()

    def _is_origin_in_scope(self, scheme: str, host: str, port: int) -> bool:
        if self.guard is None:
            return False
        if not self.guard.check_origin(scheme, host, port):
            return False
        return True

    def _canonical_origin(self, url_or_host: str, *, default_scheme: str | None = None) -> str | None:
        parts = _parse_origin_parts(url_or_host, default_scheme=default_scheme or self._default_scheme)
        return parts[0] if parts is not None else None

    def get_node(self, url_or_origin: str) -> AssetNode | None:
        origin = self._canonical_origin(url_or_origin)
        if origin is None:
            return None
        return self.nodes.get(origin)

    def add_host(
        self,
        url_or_host: str,
        *,
        role: str | None = None,
        source: str = "",
        sample_paths: Sequence[str] = (),
        alive: bool | None = None,
        status: int | None = None,
        title: str = "",
        server: str = "",
        powered_by: str = "",
        waf_vendor: str = "",
        tech_signals: Sequence[str] = (),
        default_scheme: str | None = None,
        allow_out_of_scope: bool = True,
    ) -> AssetNode | None:
        """Add or update a host/origin node while strictly enforcing ScopeGuard."""
        parts = _parse_origin_parts(url_or_host, default_scheme=default_scheme or self._default_scheme)
        if parts is None:
            return None
        origin, scheme, host, port, url_path = parts
        in_scope = self._is_origin_in_scope(scheme, host, port)
        if not in_scope:
            self.rejected_origins.add(origin)
            if not allow_out_of_scope:
                return None

        collected_paths: list[str] = list(sample_paths)
        if url_path and ("://" in str(url_or_host) or "/" in str(url_or_host)):
            collected_paths.append(url_path)

        clean_role = str(role or "").strip().lower()
        if clean_role not in VALID_ROLES:
            clean_role = ""

        existing = self.nodes.get(origin)
        if existing is None:
            norm_paths = _normalize_sample_paths(collected_paths)
            eff_role = clean_role if clean_role and clean_role != "unknown" else _infer_host_role(host, norm_paths)
            node = AssetNode(
                origin=origin,
                scheme=scheme,
                host=host,
                port=port,
                in_scope=in_scope,
                role=eff_role,
                alive=alive,
                status=_coerce_status(status),
                title=title,
                server=server,
                powered_by=powered_by,
                waf_vendor=waf_vendor,
                tech_signals=list(tech_signals),
                sample_paths=norm_paths,
                sources=[source] if source else [],
            )
            self.nodes[origin] = node
            return node

        existing.in_scope = in_scope
        if source and source not in existing.sources:
            existing.sources = sorted({*existing.sources, source})
        if collected_paths:
            existing.sample_paths = _normalize_sample_paths([*existing.sample_paths, *collected_paths])
        if alive is not None:
            existing.alive = alive
        coerced_status = _coerce_status(status)
        if coerced_status is not None:
            existing.status = coerced_status
        if title:
            existing.title = _sanitize_single_line(title, max_len=MAX_TITLE_CHARS)
        if server:
            existing.server = _sanitize_single_line(server, max_len=MAX_META_CHARS)
        if powered_by:
            existing.powered_by = _sanitize_single_line(powered_by, max_len=MAX_META_CHARS)
        if waf_vendor:
            existing.waf_vendor = _sanitize_single_line(waf_vendor, max_len=64)
        if tech_signals:
            existing.tech_signals = sorted({*existing.tech_signals, *(str(t).strip() for t in tech_signals if str(t).strip())})

        if clean_role and clean_role != "unknown":
            if (
                existing.role == "unknown"
                or alive is True
                or (existing.role == "storefront" and clean_role in {"api", "auth", "graphql", "admin"})
            ):
                existing.role = clean_role
        elif existing.role == "unknown":
            existing.role = _infer_host_role(existing.host, existing.sample_paths)
        return existing

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        *,
        evidence: str = "",
        source_tag: str = "",
        allow_out_of_scope: bool = True,
    ) -> AssetEdge | None:
        """Record a directed relationship between two origins."""
        src_parts = _parse_origin_parts(source, default_scheme=self._default_scheme)
        dst_parts = _parse_origin_parts(target, default_scheme=self._default_scheme)
        if src_parts is None or dst_parts is None:
            return None
        src_origin = src_parts[0]
        dst_origin = dst_parts[0]
        if src_origin == dst_origin:
            return None

        if src_origin not in self.nodes:
            src_node = self.add_host(src_origin, source=source_tag, allow_out_of_scope=allow_out_of_scope)
            if src_node is None:
                return None
        if dst_origin not in self.nodes:
            dst_role_hint = "cdn" if relation == "loads_cdn_js" else ("auth" if relation == "authenticates_at" else None)
            dst_node = self.add_host(
                dst_origin,
                role=dst_role_hint,
                source=source_tag,
                allow_out_of_scope=allow_out_of_scope,
            )
            if dst_node is None:
                return None

        norm_rel = _sanitize_single_line(relation, max_len=48).lower().replace(" ", "_") or "references"
        clean_evidence = _sanitize_single_line(evidence, max_len=160)
        key = (src_origin, dst_origin, norm_rel)
        existing = self.edges.get(key)
        if existing is None:
            edge = AssetEdge(
                source=src_origin,
                target=dst_origin,
                relation=norm_rel,
                evidence=clean_evidence,
                sources=[source_tag] if source_tag else [],
            )
            self.edges[key] = edge
            return edge

        if clean_evidence and not existing.evidence:
            existing.evidence = clean_evidence
        if source_tag and source_tag not in existing.sources:
            existing.sources = sorted({*existing.sources, source_tag})
        return existing

    def in_scope_nodes(self) -> list[AssetNode]:
        return [node for node in self.nodes.values() if node.in_scope]

    def out_of_scope_nodes(self) -> list[AssetNode]:
        return [node for node in self.nodes.values() if not node.in_scope]

    def ingest_scope_doc(
        self,
        scope_doc: dict[str, Any],
        *,
        source: str = "scope_file",
    ) -> list[AssetNode]:
        """Ingest concrete in-scope origins from a validated scope.json document."""
        if not isinstance(scope_doc, dict):
            return []
        added: list[AssetNode] = []
        for entry in scope_doc.get("in_scope") or []:
            rule = _parse_scope_asset(entry)
            if rule is None:
                continue
            if rule.host_pattern.startswith("*."):
                continue
            scheme = rule.scheme or self._default_scheme
            port = rule.port if rule.port is not None else _default_port(scheme)
            origin = _format_origin(scheme, rule.host_pattern, port)
            sample_paths = [rule.path] if rule.path and rule.path != "/" else []
            node = self.add_host(
                origin,
                source=source,
                sample_paths=sample_paths,
                default_scheme=scheme,
                allow_out_of_scope=False,
            )
            if node is not None:
                added.append(node)
        return added

    def ingest_stage0_seed(
        self,
        seed_doc: dict[str, Any],
        *,
        source: str = "stage0",
    ) -> int:
        """Ingest base URL, discovered_api_hosts, and route origins from a stage0-seed/1 document."""
        if not isinstance(seed_doc, dict):
            return 0
        count = 0
        base_raw = str(seed_doc.get("url") or self.base_origin).strip()
        base_origin = self._canonical_origin(base_raw) or self.base_origin
        if base_origin:
            if self.add_host(base_origin, source=source) is not None:
                count += 1

        for item in seed_doc.get("discovered_api_hosts") or []:
            if not isinstance(item, dict):
                continue
            raw_origin = str(item.get("origin") or item.get("host") or "").strip()
            if not raw_origin:
                continue
            parts = _parse_origin_parts(raw_origin, default_scheme=self._default_scheme)
            if parts is None or _is_tracker_host(parts[2]):
                continue
            sample_paths = [str(p) for p in (item.get("sample_paths") or []) if isinstance(p, str)]
            role_guess = _infer_host_role(parts[2], sample_paths)
            if role_guess == "unknown":
                role_guess = "api"
            node = self.add_host(
                parts[0],
                role=role_guess,
                source=source,
                sample_paths=sample_paths,
            )
            if node is not None:
                count += 1
                if base_origin and base_origin != node.origin:
                    rel = (
                        "authenticates_at"
                        if node.role == "auth"
                        else ("loads_cdn_js" if node.role == "cdn" else "calls_api")
                    )
                    ev = node.sample_paths[0] if node.sample_paths else ""
                    self.add_edge(base_origin, node.origin, rel, evidence=ev, source_tag=source)

        for key in ("links", "forms", "discovery_hints"):
            for entry in seed_doc.get(key) or []:
                raw_u = ""
                if isinstance(entry, str):
                    raw_u = entry.strip()
                elif isinstance(entry, dict):
                    raw_u = str(entry.get("url") or entry.get("path") or "").strip()
                if not raw_u:
                    continue
                if "://" in raw_u:
                    parts = _parse_origin_parts(raw_u)
                    if parts is None or _is_tracker_host(parts[2]):
                        continue
                    node = self.add_host(parts[0], source=source, sample_paths=[parts[4]])
                    if node is not None:
                        count += 1
                        if base_origin and base_origin != node.origin:
                            rel = "authenticates_at" if node.role == "auth" else "calls_api"
                            self.add_edge(base_origin, node.origin, rel, evidence=parts[4], source_tag=source)
                elif raw_u.startswith("/") and base_origin:
                    self.add_host(base_origin, source=source, sample_paths=[raw_u])

        return count

    def ingest_har(
        self,
        har_doc: dict[str, Any],
        *,
        source: str = "har",
    ) -> int:
        """Ingest non-secret hosts, paths, and edges from a HAR 1.2 archive."""
        if not isinstance(har_doc, dict):
            return 0
        log = har_doc.get("log")
        if not isinstance(log, dict):
            return 0
        entries = log.get("entries")
        if not isinstance(entries, list):
            return 0

        page_origins: dict[str, str] = {}
        for page in log.get("pages") or []:
            if not isinstance(page, dict):
                continue
            pid = str(page.get("id") or "").strip()
            purl = str(page.get("title") or page.get("url") or "").strip()
            if pid and "://" in purl:
                po = self._canonical_origin(purl)
                if po:
                    page_origins[pid] = po

        count = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            req = entry.get("request")
            if not isinstance(req, dict):
                continue
            raw_url = str(req.get("url") or "").strip()
            parts = _parse_origin_parts(raw_url)
            if parts is None:
                continue
            origin, _scheme, host, _port, path = parts
            if _is_tracker_host(host) and not self._is_origin_in_scope(_scheme, host, _port):
                continue

            req_method = str(req.get("method") or "GET").strip().upper()
            initiator_origin = ""
            for hdr in req.get("headers") or []:
                if isinstance(hdr, dict):
                    hname = str(hdr.get("name") or "").strip().lower()
                    if hname in {"origin", "referer"}:
                        cand = self._canonical_origin(str(hdr.get("value") or "").strip())
                        if cand:
                            initiator_origin = cand
                            if hname == "origin":
                                break
            if not initiator_origin:
                pageref = str(entry.get("pageref") or "").strip()
                initiator_origin = page_origins.get(pageref, self.base_origin)

            raw_resp = entry.get("response")
            resp: dict[str, Any] = raw_resp if isinstance(raw_resp, dict) else {}
            status = _coerce_status(resp.get("status"))
            resp_headers: dict[str, str] = {}
            for hdr in resp.get("headers") or []:
                if isinstance(hdr, dict):
                    hname = str(hdr.get("name") or "").strip()
                    hval = str(hdr.get("value") or "").strip()
                    if hname.lower() in _NON_SECRET_RESPONSE_HEADERS and hval:
                        resp_headers[hname] = hval

            raw_content = resp.get("content")
            content_obj: dict[str, Any] = raw_content if isinstance(raw_content, dict) else {}
            mime = str(content_obj.get("mimeType") or "").split(";", 1)[0].strip().lower()
            if mime and "content-type" not in {k.lower() for k in resp_headers}:
                resp_headers["Content-Type"] = mime
            body_text = str(content_obj.get("text") or "")[:65536] if isinstance(content_obj.get("text"), str) else ""

            res_type = str(entry.get("_resourceType") or "").strip().lower()
            is_static_asset = (
                res_type in {"script", "stylesheet"}
                or _SCRIPT_EXT_RE.search(path) is not None
                or is_static_asset_url(path)
            )
            signals = _extract_response_signals(
                host=host,
                status=status,
                headers=resp_headers,
                body=body_text,
                sample_paths=[path],
            )
            role_hint = signals["role"]
            if is_static_asset and initiator_origin and initiator_origin != origin and role_hint in {"unknown", "storefront"}:
                role_hint = "cdn"

            is_in_scope = self._is_origin_in_scope(_scheme, host, _port)
            node = self.add_host(
                origin,
                role=role_hint,
                source=source,
                sample_paths=[path],
                status=status if is_in_scope else None,
                alive=None,
                title=signals["title"] if is_in_scope else "",
                server=signals["server"],
                powered_by=signals["powered_by"],
                waf_vendor=signals["waf_vendor"],
                tech_signals=signals["tech_signals"],
            )
            if node is not None:
                count += 1
                if initiator_origin and initiator_origin != origin:
                    if is_static_asset or node.role == "cdn":
                        rel = "loads_cdn_js"
                    elif node.role == "auth" or _AUTH_PATH_RE.match(path):
                        rel = "authenticates_at"
                    elif req_method in {"POST", "PUT", "PATCH", "DELETE"} or node.role in {"api", "graphql"} or "json" in mime or res_type in {"xhr", "fetch"}:
                        rel = "calls_api"
                    else:
                        rel = "calls_api"
                    self.add_edge(initiator_origin, origin, rel, evidence=path, source_tag=source)

                loc = resp_headers.get("location") or resp_headers.get("Location") or ""
                if status in _REDIRECT_STATUS_CODES and loc:
                    joined = urljoin(f"{origin}{path}", loc)
                    r_parts = _parse_origin_parts(joined)
                    if r_parts is not None and r_parts[0] != origin:
                        self.add_edge(origin, r_parts[0], "redirects_to", evidence=r_parts[4], source_tag=source)
        return count

    def ingest_ct_domains(
        self,
        domains: Sequence[str],
        *,
        source: str = "ct_log",
        scheme: str | None = None,
    ) -> list[AssetNode]:
        """Ingest passive CT subdomains; strictly enforces ScopeGuard (rejects out-of-scope domains)."""
        eff_scheme = scheme if scheme in _VALID_SCHEMES else self._default_scheme
        added: list[AssetNode] = []
        for raw_dom in domains:
            dom = str(raw_dom or "").strip().lower().rstrip(".")
            if not dom or "*" in dom or not _is_valid_host(dom):
                continue
            origin = _format_origin(eff_scheme, dom, _default_port(eff_scheme))
            node = self.add_host(
                origin,
                source=source,
                default_scheme=eff_scheme,
                allow_out_of_scope=False,
            )
            if node is not None:
                added.append(node)
        return added

    def ranked_targets(self, *, include_unreachable: bool = True) -> list[AssetNode]:
        """Return in-scope nodes ranked with live api/auth/graphql/admin hosts ahead of storefront."""
        candidates = [node for node in self.nodes.values() if node.in_scope]
        if not include_unreachable:
            candidates = [node for node in candidates if node.alive is not False]

        def _sort_key(node: AssetNode) -> tuple[int, int, int, int, int, int, str]:
            alive_rank = 0 if node.alive is True else (1 if node.alive is None else 2)
            role_rank = ROLE_PRIORITY.get(node.role, ROLE_PRIORITY["unknown"])
            if node.status is not None and (200 <= node.status < 400 or node.status in {401, 403}):
                status_rank = 0
            elif node.status is not None:
                status_rank = 1
            else:
                status_rank = 2
            primary_rank = 0 if node.origin == self.base_origin else 1
            return (
                alive_rank,
                role_rank,
                status_rank,
                primary_rank,
                -len([p for p in node.sample_paths if p != "/"]),
                -len(node.tech_signals),
                node.origin,
            )

        return sorted(candidates, key=_sort_key)

    def to_dict(self) -> dict[str, Any]:
        in_scope = self.in_scope_nodes()
        out_scope = self.out_of_scope_nodes()
        ranked = self.ranked_targets()
        ranked_origins = {n.origin: idx for idx, n in enumerate(ranked)}

        ordered_nodes = sorted(
            self.nodes.values(),
            key=lambda n: (0 if n.in_scope else 1, ranked_origins.get(n.origin, 999999), n.origin),
        )
        ordered_edges = sorted(
            self.edges.values(),
            key=lambda e: (e.source, e.relation, e.target),
        )

        scope_meta: dict[str, Any] = {}
        if self.guard is not None:
            scope_meta = {
                "base_origin": self.base_origin,
                "in_scope_assets": list(self.guard.in_scope_assets),
                "out_of_scope_assets": list(self.guard.out_of_scope_assets),
                "excluded_paths": list(self.guard.excluded_paths),
            }

        return {
            "schema": SCHEMA,
            "target": self.base_origin,
            "scope": scope_meta,
            "nodes": [n.to_dict() for n in ordered_nodes],
            "edges": [e.to_dict() for e in ordered_edges],
            "ranked_targets": [
                {
                    "origin": n.origin,
                    "role": n.role,
                    "alive": n.alive,
                    "status": n.status,
                }
                for n in ranked
            ],
            "stats": {
                "total_nodes": len(ordered_nodes),
                "in_scope_hosts": len(in_scope),
                "out_of_scope_hosts": len(out_scope),
                "alive_hosts": sum(1 for n in in_scope if n.alive is True),
                "dead_hosts": sum(1 for n in in_scope if n.alive is False),
                "unprobed_hosts": sum(1 for n in in_scope if n.alive is None),
                "edges_count": len(ordered_edges),
            },
        }

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        guard: ScopeGuard | None = None,
    ) -> AssetGraph:
        if not isinstance(data, dict):
            raise ValueError("asset graph payload must be a JSON object")
        if data.get("schema") != SCHEMA:
            raise ValueError(f"unsupported asset graph schema: {data.get('schema')!r}")

        target = str(data.get("target") or "").strip()
        if guard is None:
            raw_scope = data.get("scope")
            scope_doc: dict[str, Any] = raw_scope if isinstance(raw_scope, dict) else {}
            base = str(scope_doc.get("base_origin") or target).strip()
            if base:
                guard = ScopeGuard(
                    base,
                    excluded_paths=tuple(scope_doc.get("excluded_paths") or ()),
                    in_scope_assets=tuple(scope_doc.get("in_scope_assets") or ()),
                    out_of_scope_assets=tuple(scope_doc.get("out_of_scope_assets") or ()),
                )

        graph = cls(guard=guard, base_origin=target)
        for raw_node in data.get("nodes") or []:
            if not isinstance(raw_node, dict):
                continue
            node = AssetNode.from_dict(raw_node)
            if not node.origin:
                continue
            node.in_scope = graph._is_origin_in_scope(node.scheme, node.host, node.port)
            graph.nodes[node.origin] = node

        for raw_edge in data.get("edges") or []:
            if not isinstance(raw_edge, dict):
                continue
            edge = AssetEdge.from_dict(raw_edge)
            if edge.source and edge.target and edge.source != edge.target:
                graph.edges[(edge.source, edge.target, edge.relation)] = edge

        return graph

    def render_markdown(self) -> str:
        """Render a deterministic, secret-free Markdown recon summary."""
        def _cell(val: Any) -> str:
            return _sanitize_single_line(val, max_len=120).replace("|", "\\|")

        in_scope = self.ranked_targets()
        out_scope = sorted(self.out_of_scope_nodes(), key=lambda n: n.origin)
        alive_count = sum(1 for n in in_scope if n.alive is True)
        lines: list[str] = [
            f"# Recon Asset Graph Summary: {self.base_origin}",
            "",
            f"- **Schema:** `{SCHEMA}`",
            f"- **Primary Target:** `{self.base_origin}`",
            f"- **In-Scope Hosts:** {len(in_scope)} (alive: {alive_count})",
            f"- **Out-of-Scope / Context Hosts:** {len(out_scope)}",
            f"- **Observed Relationships:** {len(self.edges)}",
            "",
            "## Ranked In-Scope Targets",
            "",
        ]
        if in_scope:
            lines.extend([
                "| Rank | Origin | Role | Alive | Status | Title | Tech / WAF | Sources |",
                "|---:|---|---|---|---|---|---|---|",
            ])
            for idx, node in enumerate(in_scope, start=1):
                alive_str = "yes" if node.alive is True else ("no" if node.alive is False else "unprobed")
                status_str = str(node.status) if node.status is not None else "-"
                tech_parts = list(node.tech_signals)
                if node.server:
                    tech_parts.append(f"server={node.server}")
                if node.powered_by:
                    tech_parts.append(f"powered_by={node.powered_by}")
                if node.waf_vendor and f"waf:{node.waf_vendor}" not in tech_parts:
                    tech_parts.append(f"waf:{node.waf_vendor}")
                tech_str = ", ".join(sorted(set(tech_parts))) or "-"
                src_str = ", ".join(node.sources) or "-"
                lines.append(
                    f"| {idx} | `{_cell(node.origin)}` | `{_cell(node.role)}` | {alive_str} "
                    f"| {status_str} | {_cell(node.title) or '-'} | {_cell(tech_str)} | {_cell(src_str)} |"
                )
        else:
            lines.append("_No in-scope hosts recorded._")

        if out_scope:
            lines.extend([
                "",
                "## Out-of-Scope / External Context Hosts (Never Probed)",
                "",
                "| Origin | Role | Sources |",
                "|---|---|---|",
            ])
            for node in out_scope:
                lines.append(
                    f"| `{_cell(node.origin)}` | `{_cell(node.role)}` | {_cell(', '.join(node.sources) or '-')} |"
                )

        lines.extend(["", "## Asset Relationships", ""])
        if self.edges:
            for edge in sorted(self.edges.values(), key=lambda e: (e.source, e.relation, e.target)):
                ev = f" (`{_cell(edge.evidence)}`)" if edge.evidence else ""
                lines.append(f"- `{_cell(edge.source)}` --**{_cell(edge.relation)}**--> `{_cell(edge.target)}`{ev}")
        else:
            lines.append("_No cross-origin relationships observed._")

        lines.append("")
        return "\n".join(lines)


def _call_ct_fetcher(
    fetcher: Callable[..., Any],
    url: str,
    timeout_s: float,
    max_bytes: int,
) -> Any:
    try:
        sig = inspect.signature(fetcher)
        params = list(sig.parameters.values())
        accepts_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
        accepts_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        param_names = {p.name for p in params}
    except (TypeError, ValueError):
        return fetcher(url)

    kwargs: dict[str, Any] = {}
    if accepts_varkw or "timeout_s" in param_names:
        kwargs["timeout_s"] = timeout_s
    elif "timeout" in param_names:
        kwargs["timeout"] = timeout_s
    if accepts_varkw or "max_bytes" in param_names:
        kwargs["max_bytes"] = max_bytes

    if accepts_varargs:
        return fetcher(url, **kwargs)
    pos_count = sum(
        1 for p in params
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        and p.name not in kwargs
    )
    if pos_count >= 1:
        return fetcher(url, **kwargs)
    return fetcher(**kwargs)


def fetch_ct_subdomains(
    domain: str,
    *,
    timeout_s: float = 8.0,
    max_bytes: int = MAX_CT_RESPONSE_BYTES,
    fetcher: Callable[..., Any] | None = None,
) -> list[str]:
    """Passively query crt.sh JSON logs for subdomains of ``domain`` with strict size/timeout caps."""
    raw_dom = str(domain or "").strip().lower().rstrip(".")
    if "://" in raw_dom:
        raw_dom = (urlsplit(raw_dom).hostname or "").strip().lower().rstrip(".")
    if raw_dom.startswith("*."):
        raw_dom = raw_dom[2:]
    if not raw_dom or _is_loopback_or_private_host(raw_dom) or not _is_valid_host(raw_dom):
        return []

    eff_timeout = max(0.5, min(float(timeout_s), 30.0))
    eff_max_bytes = max(1024, min(int(max_bytes), MAX_CT_RESPONSE_BYTES))
    crt_url = f"https://crt.sh/?q=%25.{quote(raw_dom, safe='')}&output=json"

    if fetcher is not None:
        raw_payload = _call_ct_fetcher(fetcher, crt_url, eff_timeout, eff_max_bytes)
    else:
        parsed_crt = urlsplit(crt_url)
        if parsed_crt.scheme != "https" or (parsed_crt.hostname or "").lower() != "crt.sh":
            raise ValueError("invalid crt.sh URL")
        req = urllib.request.Request(
            crt_url,
            headers={
                "User-Agent": DEFAULT_BROWSER_USER_AGENT,
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=eff_timeout) as resp:  # nosec - hardcoded https://crt.sh
            raw_bytes = resp.read(eff_max_bytes + 1)
            if len(raw_bytes) > eff_max_bytes:
                raise ValueError(f"crt.sh response exceeds max size of {eff_max_bytes} bytes")
            raw_payload = raw_bytes

    parsed: Any
    if isinstance(raw_payload, (bytes, bytearray)):
        if len(raw_payload) > eff_max_bytes:
            raise ValueError(f"crt.sh response exceeds max size of {eff_max_bytes} bytes")
        parsed = json.loads(bytes(raw_payload).decode("utf-8", errors="replace"))
    elif isinstance(raw_payload, str):
        encoded_len = len(raw_payload.encode("utf-8", errors="replace"))
        if encoded_len > eff_max_bytes:
            raise ValueError(f"crt.sh response exceeds max size of {eff_max_bytes} bytes")
        parsed = json.loads(raw_payload)
    elif isinstance(raw_payload, list):
        parsed = raw_payload
    else:
        return []

    if not isinstance(parsed, list):
        return []

    found: set[str] = set()
    for item in parsed:
        if isinstance(item, str):
            candidates = item.splitlines()
        elif isinstance(item, dict):
            candidates = []
            for key in ("name_value", "common_name", "dns_name", "host", "domain"):
                val = item.get(key)
                if isinstance(val, str) and val.strip():
                    candidates.extend(val.splitlines())
        else:
            continue
        for cand in candidates:
            host = cand.strip().lower().rstrip(".")
            if not host or "*" in host or not _is_valid_host(host):
                continue
            found.add(host)
    return sorted(found)


def _ingest_generic_seed_file(graph: AssetGraph, path: Path | str) -> str:
    text = _read_regular_file(path)
    stripped = text.strip()
    if not stripped:
        return "empty"

    if stripped[0] in "{[":
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            if isinstance(parsed.get("log"), dict) and isinstance(parsed["log"].get("entries"), list):
                graph.ingest_har(parsed, source="har")
                return "har"
            if str(parsed.get("schema") or "").startswith("stage0-seed/") or "discovered_api_hosts" in parsed:
                graph.ingest_stage0_seed(parsed, source="stage0")
                return "stage0_seed"
            if any(k in parsed for k in ("links", "forms", "routes", "endpoints", "urls", "discovery_hints")):
                graph.ingest_stage0_seed(parsed, source="seed")
                return "seed_json"
        if isinstance(parsed, list):
            for entry in parsed:
                raw_u = ""
                if isinstance(entry, str):
                    raw_u = entry.strip()
                elif isinstance(entry, dict):
                    raw_u = str(
                        entry.get("url")
                        or entry.get("matched-at")
                        or entry.get("matched_at")
                        or entry.get("host")
                        or ""
                    ).strip()
                if "://" in raw_u:
                    parts = _parse_origin_parts(raw_u)
                    if parts is not None and not _is_tracker_host(parts[2]):
                        graph.add_host(parts[0], source="seed", sample_paths=[parts[4]])
            return "seed_json_list"

    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        cand = tokens[-1] if len(tokens) == 2 and tokens[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} else line
        if "://" in cand:
            parts = _parse_origin_parts(cand)
            if parts is not None and not _is_tracker_host(parts[2]):
                graph.add_host(parts[0], source="seed", sample_paths=[parts[4]])
        elif cand.startswith("/") and graph.base_origin:
            graph.add_host(graph.base_origin, source="seed", sample_paths=[cand])
    return "seed_text"


def _read_bounded_response(resp: Any, max_bytes: int) -> tuple[int, dict[str, str], str]:
    status = int(getattr(resp, "status_code", 0) or 0)
    raw_headers = getattr(resp, "headers", None) or {}
    resp_headers = {str(k): str(v) for k, v in raw_headers.items()}

    raw_bytes = b""
    iter_fn = getattr(resp, "iter_content", None)
    if callable(iter_fn):
        chunks: list[bytes] = []
        total = 0
        try:
            for chunk in iter_fn(chunk_size=8192):
                if not chunk:
                    continue
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            raw_bytes = b"".join(chunks)[:max_bytes]
        except Exception:
            raw_bytes = b""

    if not raw_bytes:
        raw_content = getattr(resp, "content", None)
        if isinstance(raw_content, (bytes, bytearray)):
            raw_bytes = bytes(raw_content)[:max_bytes]
        elif isinstance(getattr(resp, "text", None), str):
            return status, resp_headers, str(resp.text)[:max_bytes]

    return status, resp_headers, raw_bytes.decode("utf-8", errors="replace")


def _extract_robots_paths(robots_text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in (robots_text or "").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        directive, _, val = line.partition(":")
        if directive.strip().lower() not in {"disallow", "allow"}:
            continue
        cand = val.strip().split("*", 1)[0].strip()
        if not cand or cand == "/" or not _SAFE_ROBOTS_PATH_RE.fullmatch(cand):
            continue
        try:
            norm = normalize_path(cand)
        except ValueError:
            continue
        if norm != "/" and norm not in paths:
            paths.append(norm)
            if len(paths) >= 10:
                break
    return paths


def _build_recommended_scope_doc(
    graph: AssetGraph,
    *,
    scope_doc: dict[str, Any] | None,
    guard: ScopeGuard,
) -> dict[str, Any]:
    alive_in_scope = [node.origin for node in graph.ranked_targets(include_unreachable=False) if node.alive is True]
    out_of_scope: list[Any] = []
    if isinstance(scope_doc, dict) and isinstance(scope_doc.get("out_of_scope"), list):
        out_of_scope = list(scope_doc["out_of_scope"])
    elif guard.out_of_scope_assets:
        out_of_scope = list(guard.out_of_scope_assets)

    recommended: dict[str, Any] = {
        "schema": SCOPE_RECOMMENDED_SCHEMA,
        "target": graph.base_origin,
        "in_scope": alive_in_scope,
        "out_of_scope": out_of_scope,
        "excluded_paths": list(guard.excluded_paths),
    }
    if isinstance(scope_doc, dict) and isinstance(scope_doc.get("excluded_assets"), list) and scope_doc["excluded_assets"]:
        recommended["excluded_assets"] = list(scope_doc["excluded_assets"])
    return recommended


def run_recon(
    *,
    target: str,
    output_dir: Path | str,
    scope_file: Path | str | None = None,
    allow_non_loopback: bool = False,
    seed_files: Sequence[Path | str] | None = None,
    custom_headers: Sequence[str] | dict[str, Any] | None = None,
    passive_ct: bool = False,
    max_requests: int = 40,
    max_rps: float = 2.0,
    timeout_s: float = 8.0,
    execute: bool = False,
    ct_fetcher: Callable[..., Any] | None = None,
    http_session_factory: Callable[[], Any] | None = None,
) -> tuple[Path, dict[str, Any]]:
    """Run offline recon planning (execute=False) or scope-locked live probing (execute=True)."""
    if output_dir is None or not str(output_dir).strip():
        raise ValueError("output_dir is required")
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or max_requests < 0:
        raise ValueError("max_requests must be a non-negative integer")
    if isinstance(max_rps, bool):
        raise ValueError("max_rps must be a finite number >= 0.0")
    eff_max_rps = float(max_rps)
    if not math.isfinite(eff_max_rps) or eff_max_rps < 0.0:
        raise ValueError(f"max_rps must be a finite number >= 0.0, got {max_rps!r}")
    if isinstance(timeout_s, bool):
        raise ValueError("timeout_s must be a positive finite number")
    eff_timeout_s = float(timeout_s)
    if not math.isfinite(eff_timeout_s) or eff_timeout_s <= 0.0:
        raise ValueError(f"timeout_s must be a positive finite number, got {timeout_s!r}")

    cli_headers = parse_custom_headers(custom_headers)
    scope_path = Path(scope_file).expanduser() if scope_file is not None else None
    base_origin_slash, scope_meta = resolve_target_origin(
        target,
        scope_file=scope_path,
        allow_non_loopback=bool(allow_non_loopback),
    )
    scope_doc = load_scope_file(scope_path) if scope_path is not None else None
    scope_headers = parse_custom_headers(scope_meta.get("custom_headers"))
    effective_headers = _merge_header_maps(scope_headers, cli_headers)

    guard = ScopeGuard(
        base_origin_slash,
        excluded_paths=tuple(scope_meta.get("excluded_paths") or ()),
        in_scope_assets=tuple(scope_meta.get("in_scope_assets") or ()),
        out_of_scope_assets=tuple(scope_meta.get("out_of_scope_assets") or ()),
    )

    graph = AssetGraph(guard=guard, base_origin=base_origin_slash)
    graph.add_host(base_origin_slash, source="target")
    if scope_doc is not None and not scope_meta.get("loopback_only", True):
        graph.ingest_scope_doc(scope_doc, source="scope_file")

    seed_formats: list[str] = []
    for raw_seed in seed_files or ():
        fmt = _ingest_generic_seed_file(graph, raw_seed)
        if fmt not in seed_formats:
            seed_formats.append(fmt)

    out_path = Path(output_dir).expanduser().resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    if not execute:
        ranked_plan = graph.ranked_targets()
        plan_path = out_path / "recon-plan.json"
        plan_doc: dict[str, Any] = {
            "schema": PLAN_SCHEMA,
            "mode": "plan_only",
            "target": graph.base_origin,
            "scope": {
                "loopback_only": bool(scope_meta.get("loopback_only", True)),
                "scope_file": scope_meta.get("scope_file"),
                "in_scope_assets_count": len(guard.in_scope_assets),
                "out_of_scope_assets_count": len(guard.out_of_scope_assets),
                "excluded_paths_count": len(guard.excluded_paths),
            },
            "request_headers": sorted(effective_headers.keys()),
            "passive_ct": bool(passive_ct),
            "seed_formats": seed_formats,
            "limits": {
                "max_requests": int(max_requests),
                "max_rps": eff_max_rps,
                "timeout_s": eff_timeout_s,
            },
            "in_scope_hosts": [node.origin for node in ranked_plan],
            "out_of_scope_hosts": sorted(n.origin for n in graph.out_of_scope_nodes()),
            "alive_hosts": [],
            "requests_sent": 0,
            "recommended_targets": [
                {"origin": node.origin, "role": node.role, "alive": node.alive, "status": node.status}
                for node in ranked_plan
            ],
            "asset_graph": graph.to_dict(),
        }
        _write_json_atomic(plan_path, plan_doc)
        return plan_path, plan_doc

    # Live mode (execute=True): passive CT (optional) -> WireBudget-paced ScopeGuard-verified probing.
    ct_errors: list[str] = []
    if passive_ct:
        ct_domains_to_query: list[str] = []
        target_parts = _parse_origin_parts(graph.base_origin)
        if target_parts is not None and not _is_loopback_or_private_host(target_parts[2]):
            reg = _registrable_domain(target_parts[2])
            if reg:
                ct_domains_to_query.append(reg)
        for asset in guard.in_scope_assets:
            rule = _parse_scope_asset(asset)
            if rule is not None and rule.host_pattern.startswith("*."):
                base_dom = rule.host_pattern[2:]
                if base_dom and not _is_loopback_or_private_host(base_dom) and base_dom not in ct_domains_to_query:
                    ct_domains_to_query.append(base_dom)

        for dom in ct_domains_to_query:
            try:
                discovered = fetch_ct_subdomains(dom, timeout_s=eff_timeout_s, fetcher=ct_fetcher)
                graph.ingest_ct_domains(discovered, source="ct_log", scheme=graph._default_scheme)
            except Exception as exc:
                ct_errors.append(f"{dom}: {type(exc).__name__}")

    budget = WireBudget(int(max_requests), uuid.uuid4().hex)
    wire_headers = dict(effective_headers)
    if not any(k.lower() == "user-agent" for k in wire_headers):
        wire_headers["User-Agent"] = DEFAULT_BROWSER_USER_AGENT

    session = http_session_factory() if http_session_factory is not None else requests.Session()
    if hasattr(session, "trust_env"):
        try:
            session.trust_env = False
        except Exception:
            pass

    last_request_at: float | None = None
    probed_origins: set[str] = set()
    budget_exhausted = False

    def _pace_rate_limit() -> None:
        nonlocal last_request_at
        if eff_max_rps <= 0.0:
            last_request_at = time.monotonic()
            return
        interval = 1.0 / eff_max_rps
        now = time.monotonic()
        if last_request_at is not None:
            wait_s = (last_request_at + interval) - now
            if wait_s > 0.0:
                time.sleep(wait_s)
        last_request_at = time.monotonic()

    def _send_readonly_get(probe_url: str) -> tuple[int, dict[str, str], str, bool]:
        nonlocal budget_exhausted
        guard.check_url(probe_url)
        allowed, _reason = budget.consume()
        if not allowed:
            budget_exhausted = True
            return 0, {}, "", False

        _pace_rate_limit()
        cookies = getattr(session, "cookies", None)
        if cookies is not None and callable(getattr(cookies, "clear", None)):
            cookies.clear()
        try:
            req_fn = getattr(session, "request", None)
            if callable(req_fn):
                try:
                    resp = req_fn(
                        "GET",
                        probe_url,
                        headers=dict(wire_headers),
                        allow_redirects=False,
                        timeout=eff_timeout_s,
                        stream=True,
                    )
                except TypeError:
                    resp = req_fn(
                        "GET",
                        probe_url,
                        headers=dict(wire_headers),
                        allow_redirects=False,
                        timeout=eff_timeout_s,
                    )
            else:
                resp = session.get(
                    probe_url,
                    headers=dict(wire_headers),
                    allow_redirects=False,
                    timeout=eff_timeout_s,
                )
            try:
                status, resp_headers, body_text = _read_bounded_response(resp, MAX_PROBE_BODY_BYTES)
            finally:
                close_fn = getattr(resp, "close", None)
                if callable(close_fn):
                    close_fn()
            return status, resp_headers, body_text, True
        except Exception:
            return 0, {}, "", True
        finally:
            if cookies is not None and callable(getattr(cookies, "clear", None)):
                cookies.clear()

    try:
        # Pass 1: probe GET / on in-scope candidate origins in priority order.
        queue = [node.origin for node in graph.ranked_targets()]
        while queue and not budget_exhausted:
            origin = queue.pop(0)
            if origin in probed_origins:
                continue
            node = graph.nodes.get(origin)
            if node is None or not node.in_scope:
                continue
            if not guard.check_origin(node.scheme, node.host, node.port):
                node.in_scope = False
                continue

            probe_url = f"{origin}/"
            try:
                guard.check_url(probe_url)
            except ValueError:
                continue

            probed_origins.add(origin)
            status, resp_headers, body_text, attempted = _send_readonly_get(probe_url)
            if not attempted:
                break

            if status == 0:
                node.alive = False
                node.status = None
                continue

            node.alive = True
            node.status = status
            signals = _extract_response_signals(
                host=node.host,
                status=status,
                headers=resp_headers,
                body=body_text,
                sample_paths=node.sample_paths,
            )
            node.title = signals["title"] or node.title
            node.server = signals["server"] or node.server
            node.powered_by = signals["powered_by"] or node.powered_by
            node.waf_vendor = signals["waf_vendor"] or node.waf_vendor
            node.tech_signals = sorted({*node.tech_signals, *signals["tech_signals"]})
            if signals["role"] != "unknown":
                node.role = signals["role"]

            # Inspect non-followed redirects strictly within ScopeGuard.
            location = ""
            for hk, hv in resp_headers.items():
                if hk.lower() == "location":
                    location = hv.strip()
                    break
            if status in _REDIRECT_STATUS_CODES and location and not location.startswith("//"):
                joined = urljoin(probe_url, location)
                redir_parts = _parse_origin_parts(joined)
                if redir_parts is not None:
                    r_origin, _r_scheme, _r_host, _r_port, r_path = redir_parts
                    if r_origin == origin:
                        if r_path and r_path != "/":
                            node.sample_paths = _normalize_sample_paths([*node.sample_paths, r_path])
                    else:
                        redir_node = graph.add_host(
                            r_origin,
                            source="redirect",
                            sample_paths=[r_path],
                        )
                        graph.add_edge(origin, r_origin, "redirects_to", evidence=r_path, source_tag="probe")
                        if redir_node is not None and redir_node.in_scope and r_origin not in probed_origins and r_origin not in queue:
                            queue.append(r_origin)

            # Extract same-registrable or in-scope origin references from HTML/JSON body (passive).
            if body_text:
                for match in _ABS_URL_RE.findall(body_text[:131072]):
                    m_parts = _parse_origin_parts(match)
                    if m_parts is None or m_parts[0] == origin or _is_tracker_host(m_parts[2]):
                        continue
                    if graph._is_origin_in_scope(m_parts[1], m_parts[2], m_parts[3]):
                        m_node = graph.add_host(m_parts[0], source="probe_body", sample_paths=[m_parts[4]])
                        if m_node is not None:
                            rel = (
                                "authenticates_at"
                                if m_node.role == "auth"
                                else ("loads_cdn_js" if m_node.role == "cdn" else "calls_api")
                            )
                            graph.add_edge(origin, m_node.origin, rel, evidence=m_parts[4], source_tag="probe_body")
                            if m_node.in_scope and m_node.origin not in probed_origins and m_node.origin not in queue:
                                queue.append(m_node.origin)

        # Pass 2: optional /robots.txt only on alive in-scope origins if WireBudget still allows.
        for node in graph.ranked_targets(include_unreachable=False):
            if budget_exhausted or budget.used >= budget.limit:
                break
            if node.alive is not True or not node.in_scope:
                continue
            robots_url = f"{node.origin}/robots.txt"
            try:
                guard.check_url(robots_url)
            except ValueError:
                continue
            r_status, r_headers, r_body, attempted = _send_readonly_get(robots_url)
            if not attempted:
                break
            if r_status == 200 and r_body:
                r_ctype = next((v for k, v in r_headers.items() if k.lower() == "content-type"), "").lower()
                if "html" not in r_ctype:
                    robots_paths = _extract_robots_paths(r_body)
                    if robots_paths:
                        node.sample_paths = _normalize_sample_paths([*node.sample_paths, *robots_paths])
    finally:
        close_sess = getattr(session, "close", None)
        if callable(close_sess):
            try:
                close_sess()
            except Exception:
                pass

    graph_dict = graph.to_dict()
    graph_path = out_path / "asset-graph.json"
    _write_json_atomic(graph_path, graph_dict)

    summary_path = out_path / "recon-summary.md"
    summary_path.write_text(graph.render_markdown(), encoding="utf-8")

    scope_rec_path = out_path / "scope.recommended.json"
    scope_rec_doc = _build_recommended_scope_doc(graph, scope_doc=scope_doc, guard=guard)
    _write_json_atomic(scope_rec_path, scope_rec_doc)

    ranked_live = graph.ranked_targets()
    live_doc: dict[str, Any] = {
        **graph_dict,
        "mode": "live",
        "request_headers": sorted(effective_headers.keys()),
        "passive_ct": bool(passive_ct),
        "ct_errors": ct_errors,
        "requests_sent": int(budget.used),
        "budget_limit": int(budget.limit),
        "asset_graph": str(graph_path),
        "summary_md": str(summary_path),
        "scope_recommended": str(scope_rec_path),
        "in_scope_hosts": [node.origin for node in ranked_live],
        "alive_hosts": [node.origin for node in ranked_live if node.alive is True],
    }
    return graph_path, live_doc


def _custom_header_arg(raw: str) -> str:
    try:
        parse_custom_headers([raw])
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scope-locked pre-assessment recon, passive CT discovery, and AssetGraph builder.",
    )
    parser.add_argument("--target", required=True, help="Primary target origin (e.g. http://127.0.0.1:8000/ or https://www.target.example)")
    parser.add_argument("--scope-file", type=Path, default=None, help="Explicit scope.json file (required when --allow-non-loopback is set)")
    parser.add_argument("--allow-non-loopback", action="store_true", help="Allow non-loopback target origin authorized by --scope-file")
    parser.add_argument("--output-dir", "--output", dest="output_dir", type=Path, required=True, help="Output directory for recon artifacts")
    parser.add_argument("--seed-file", "--seed-surface", action="append", dest="seed_files", type=Path, default=None, help="Offline seed file (stage0-seed.json / HAR / URL list); repeatable")
    parser.add_argument(
        "-H",
        "--header",
        "--custom-header",
        action="append",
        dest="custom_headers",
        type=_custom_header_arg,
        default=None,
        metavar="NAME: VALUE",
        help="Operator header sent on every live probe request (repeatable; never written to disk)",
    )
    parser.add_argument("--passive-ct", action="store_true", help="Enable passive crt.sh subdomain lookup during live execution")
    parser.add_argument("--max-requests", type=int, default=40, help="Maximum HTTP probe requests (default: 40)")
    parser.add_argument("--max-rps", type=float, default=2.0, help="Maximum probe requests per second (default: 2.0)")
    parser.add_argument("--timeout", "--timeout-s", dest="timeout_s", type=float, default=8.0, help="Per-request timeout in seconds (default: 8.0)")
    parser.add_argument("--execute", action="store_true", help="Execute live scope-locked probes (omit for 0-request plan mode)")

    opts = parser.parse_args(argv)
    try:
        artifact_path, doc = run_recon(
            target=opts.target,
            output_dir=opts.output_dir,
            scope_file=opts.scope_file,
            allow_non_loopback=bool(opts.allow_non_loopback),
            seed_files=opts.seed_files,
            custom_headers=opts.custom_headers,
            passive_ct=bool(opts.passive_ct),
            max_requests=int(opts.max_requests),
            max_rps=float(opts.max_rps),
            timeout_s=float(opts.timeout_s),
            execute=bool(opts.execute),
        )
    except ValueError as exc:
        parser.error(str(exc))

    summary = {
        "artifact": str(artifact_path),
        "mode": doc.get("mode"),
        "target": doc.get("target"),
        "in_scope_hosts": len(doc.get("in_scope_hosts") or []),
        "alive_hosts": len(doc.get("alive_hosts") or []),
        "requests_sent": int(doc.get("requests_sent") or 0),
        "recommended_targets": list(doc.get("recommended_targets") or []),
        "asset_graph": doc.get("asset_graph") if doc.get("mode") == "live" else None,
        "summary_md": doc.get("summary_md") if doc.get("mode") == "live" else None,
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


__all__ = [
    "AssetEdge",
    "AssetGraph",
    "AssetNode",
    "PLAN_SCHEMA",
    "ROLE_PRIORITY",
    "SCHEMA",
    "SCOPE_RECOMMENDED_SCHEMA",
    "VALID_ROLES",
    "fetch_ct_subdomains",
    "main",
    "run_recon",
]


if __name__ == "__main__":
    raise SystemExit(main())
