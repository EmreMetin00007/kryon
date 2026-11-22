"""General-purpose passive attack-surface and depth frontier tracker.

Passively extracts routes, forms/parameters, concrete resource object URLs,
write operations, and actor coverage from every HTTP receipt at 0 extra HTTP cost.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import Any, Sequence
from urllib.parse import parse_qsl, urljoin, urlsplit

from agentic_http import is_static_asset_url, normalize_origin

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from kryon_core.surface.extract import (  # noqa: E402
    extract_html,
    extract_inline_scripts,
    extract_js,
    extract_js_calls,
    extract_json_hypermedia,
    extract_robots,
    extract_sitemap,
    extract_spa_routes,
    find_spec_urls,
)
from kryon_core.surface.openapi import LocalSchema  # noqa: E402

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
_API_PREFIX_RE = re.compile(r"^/(api(?:/v\d+)?|v\d+)(?=/|$)", re.IGNORECASE)
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
# Frontend source-module, style-preprocessor, and bundler artifact extensions
# that are not HTTP application endpoints. `.js` is intentionally excluded so
# app bundle URLs (e.g. `/assets/app.js`) remain discoverable for surface extraction.
_NON_ENDPOINT_SOURCE_EXTS = (
    ".d.ts",
    ".ts",
    ".tsx",
    ".jsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    ".scss",
    ".sass",
    ".less",
    ".styl",
    ".map",
    ".wasm",
    ".avif",
    ".webmanifest",
)
_BUNDLER_PATH_MARKERS = (
    "/node_modules/",
    "/@vite/",
    "/@fs/",
    "/@id/",
    "/__vite",
    "/@react-refresh",
)
_BUNDLER_EXACT_PATHS = frozenset({
    "/node_modules",
    "/@vite",
    "/@fs",
    "/@id",
    "/@react-refresh",
})
_FRONTEND_SOURCE_DIR_PREFIXES = (
    "/components/ui/",
    "/src/components/",
)


def is_malformed_url_path(url_or_path: str) -> bool:
    """Return True if a URL/path contains malformed path fragments.

    Rejects backslashes, quotes, JS template-literal syntax (`${`), path whitespace,
    and control characters while preserving valid OpenAPI/route templates like `{id}`.
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
    path = parsed.path or ""
    if not path:
        return False
    if "\\" in path or "${" in path:
        return True
    if any(ch in path for ch in ('"', "'", "`")):
        return True
    if any(ch.isspace() for ch in path):
        return True
    return False


def is_non_endpoint_source_path(url_or_path: str) -> bool:
    """Return True for frontend source/bundler artifact URLs or malformed path fragments.

    Preserves `.js` bundle URLs (e.g. `/assets/app.js`), legitimate API/OpenAPI/GraphQL
    routes, and valid `{id}` route templates.
    """
    if is_malformed_url_path(url_or_path):
        return True
    raw = str(url_or_path or "").strip()
    if not raw:
        return False
    try:
        path = (urlsplit(raw).path or "").strip()
    except ValueError:
        return True
    if not path or path == "/":
        return False
    norm_path = path.lower()
    while norm_path.startswith("./"):
        norm_path = norm_path[2:]
    if norm_path and not norm_path.startswith("/"):
        norm_path = "/" + norm_path
    trimmed = norm_path.rstrip("/")
    if not trimmed:
        return False
    if trimmed.endswith(_NON_ENDPOINT_SOURCE_EXTS):
        return True
    if trimmed in _BUNDLER_EXACT_PATHS or any(marker in norm_path for marker in _BUNDLER_PATH_MARKERS):
        return True
    if norm_path.startswith(_FRONTEND_SOURCE_DIR_PREFIXES):
        return True
    return False


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


def _extract_ui_resource_info(path: str) -> tuple[str, bool, str] | None:
    """Extract `(resource, is_collection, concrete_id)` from a non-API UI route, or None."""
    if is_non_endpoint_source_path(path):
        return None
    norm_p = normalize_path(path)
    if norm_p == "/" or _extract_api_prefix(norm_p) or is_static_asset_url(norm_p) or is_non_endpoint_source_path(norm_p):
        return None
    if norm_p.lower().endswith(_NON_RESOURCE_FILE_EXTS):
        return None
    segs = [seg for seg in norm_p.split("/") if seg]
    if not segs:
        return None
    resource = segs[0].lower()
    if (
        resource in _NON_RESOURCE_UI_SEGMENTS
        or resource.startswith((".", "_"))
        or is_id_segment(resource)
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
    """Normalize concrete resource ID path segments into `{id}` route templates."""
    path = normalize_path(url_or_path)
    if path == "/":
        return "/"
    segments: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if is_id_segment(seg):
            segments.append("{id}")
        else:
            segments.append(seg.lower())
    return "/" + "/".join(segments)


def _is_auth_utility_path(path: str) -> bool:
    low = path.lower()
    return any(f"/{tok}" in low or low.endswith(tok) for tok in _AUTH_PATH_TOKENS)


class SurfaceFrontierTracker:
    """Passively tracks discovered routes, per-actor objects, write ops, and untested frontier items."""

    def __init__(
        self,
        *,
        base_url: str,
        allowed_methods: Sequence[str] = ("GET", "HEAD"),
        actor_summaries: Sequence[dict[str, str]] = (),
    ):
        self.base_url = normalize_origin(base_url)
        parsed_origin = urlsplit(self.base_url)
        self._origin = (parsed_origin.scheme, parsed_origin.netloc)
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
        self.actors_by_template: dict[str, set[str]] = {}
        self.actors_by_path: dict[str, set[str]] = {}
        self.route_2xx_actors: dict[str, set[str]] = {}

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
            if val and not _PLAIN_ALNUM_VAL_RE.fullmatch(val):
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
        needs_depth = (tmpl in self.html_or_form_templates) or (p_low in _PROBE_PRIORITY_PARAM_NAMES)
        return not needs_depth

    def was_object_listed_for_actor(self, url_or_path: str, actor: str) -> bool:
        """Return True if `actor` legitimately received this concrete object ID in its own 2xx collection listing."""
        clean_actor = str(actor or "").strip()
        if not clean_actor:
            return False
        norm_p = normalize_path(url_or_path)
        if clean_actor in (self.collection_listed_objects.get(norm_p) or set()):
            return True
        entry = self.discovered_objects.get(norm_p)
        if entry and clean_actor in (entry.get("listed_by") or set()):
            return True

        # Check UI <-> API concrete sibling equivalence for the same (resource_family, concrete_id).
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
            base = f"{prefix}/{res_low}"
            base_slash = f"{base}/"
            in_prefix = any(
                p.lower() == base or p.lower().startswith(base_slash)
                for p in (self.api_prefix_routes.get(prefix) or ())
            )
            in_disc = any(
                normalize_path(p).lower() == base or normalize_path(p).lower().startswith(base_slash)
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
        if is_non_endpoint_source_path(norm_p):
            return
        api_prefix = _extract_api_prefix(norm_p)
        if api_prefix:
            if discovered or status != 404:
                self.api_prefix_routes.setdefault(api_prefix, set()).add(norm_p)
                remainder = norm_p[len(api_prefix):].lstrip("/")
                if remainder:
                    res_seg = remainder.split("/", 1)[0].lower()
                    if res_seg in self.ui_resource_families:
                        self._sync_ui_api_concrete_siblings(res_seg)
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

    def _resolve_same_origin(self, raw_url: str, current_url: str = "") -> tuple[str, str] | None:
        raw_input = str(raw_url or "")
        if is_non_endpoint_source_path(raw_input):
            return None
        raw = raw_input.strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "//")):
            return None
        base_ref = urljoin(self.base_url, current_url) if current_url else self.base_url
        resolved = urljoin(base_ref, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != self._origin:
            return None
        if is_static_asset_url(parsed.path) or is_non_endpoint_source_path(resolved):
            return None
        norm_p = normalize_path(parsed.path)
        return norm_p, parsed.query

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
    ) -> None:
        norm_method = str(method or "GET").strip().upper()
        resolved = self._resolve_same_origin(raw_url, current_url=current_url)
        if resolved is None:
            return
        norm_p, query = resolved
        tmpl = route_template_of(norm_p)

        q_names = [k.strip() for k, _ in parse_qsl(query, keep_blank_values=True) if k.strip()]
        for p in params:
            if isinstance(p, dict):
                pname = str(p.get("name") or "").strip()
            else:
                pname = str(p or "").strip()
            if pname and pname not in q_names:
                q_names.append(pname)
        if q_names:
            self.discovered_params.setdefault(tmpl, set()).update(q_names)
        if is_form:
            self.html_or_form_templates.add(tmpl)

        if norm_method in self.allowed_methods:
            display = f"{norm_p}?{ '&'.join(f'{k}=' for k in q_names[:4]) }" if q_names else norm_p
            key = (norm_method, norm_p)
            if key not in self.discovered_routes or ("?" in display and "?" not in self.discovered_routes[key]):
                self.discovered_routes[key] = display

        if norm_method in {"POST", "PUT", "PATCH"} and norm_method in self.allowed_methods:
            if not _is_auth_utility_path(norm_p):
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
        if is_non_endpoint_source_path(concrete_path):
            return
        norm_p = normalize_path(concrete_path)
        tmpl = route_template_of(norm_p)
        if "{id}" not in tmpl or "{" in norm_p or norm_p.lower().endswith((".js", ".mjs")):
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
        if norm_p.startswith("/api/") and not _is_auth_utility_path(norm_p):
            for write_m in ("PUT", "PATCH"):
                if write_m in self.allowed_methods:
                    key_w = (write_m, tmpl)
                    existing_sample = self.discovered_write_ops.get(key_w, "")
                    if not existing_sample or "{" in existing_sample:
                        self.discovered_write_ops[key_w] = norm_p

    def _extract_collection_item_paths(self, collection_path: str, parsed_json: Any, actor: str) -> None:
        """Synthesize `/api/.../<collection>/<id>` object paths from plural REST collection JSON responses."""
        norm_col = normalize_path(collection_path)
        col_tmpl = route_template_of(norm_col)
        if "{id}" in col_tmpl or not norm_col.startswith("/api/"):
            return
        last_seg = norm_col.rsplit("/", 1)[-1].lower().replace("-", "_")
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
        status = int(receipt.get("status") or 0)
        body = str(receipt.get("body") or "")
        ctype = str(receipt.get("content_type") or "").lower()

        self.exercised_actors.add(actor)
        norm_p = normalize_path(url)
        tmpl = route_template_of(norm_p)

        self.visited_method_paths.add((method, norm_p))
        self.visited_method_templates.add((method, tmpl))
        self.actors_by_path.setdefault(norm_p, set()).add(actor)
        self.actors_by_template.setdefault(tmpl, set()).add(actor)

        parsed_url = urlsplit(url)
        query_str = str(receipt.get("query") or parsed_url.query or "")
        q_pairs = [(k.strip(), v) for k, v in parse_qsl(query_str, keep_blank_values=True) if k.strip()]
        if q_pairs:
            self._record_param_probes(tmpl, q_pairs)

        is_html_resp = (
            "html" in ctype
            or "<html" in body[:512].lower()
            or "<form" in body.lower()
        )
        is_redirect_resp = 300 <= status < 400 and bool(str(receipt.get("redirect_location") or "").strip())
        if 200 <= status < 400 and (is_html_resp or is_redirect_resp):
            self.html_or_form_templates.add(tmpl)
            if q_pairs:
                non_meta_keys = {k for k, _ in q_pairs if k.lower() not in _NON_PROBE_PARAM_NAMES}
                if non_meta_keys:
                    self.discovered_params.setdefault(tmpl, set()).update(non_meta_keys)

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            req_body = str(receipt.get("request_body") or "")
            body_pairs = [(k.strip(), v) for k, v in parse_qsl(req_body, keep_blank_values=True) if k.strip()]
            if body_pairs:
                self._record_param_probes(tmpl, body_pairs)
            if not _is_auth_utility_path(norm_p):
                self.tested_write_ops.add((method, tmpl))

        if 200 <= status < 300:
            self.route_2xx_actors.setdefault(norm_p, set()).add(actor)

        self._observe_parity_path(norm_p, discovered=False, status=status, ctype=ctype)

        # Track concrete object visits
        if "{id}" in tmpl and "{" not in norm_p and 200 <= status < 300:
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

        # Follow same-origin redirect Location
        loc = str(receipt.get("redirect_location") or "").strip()
        if loc:
            self._register_discovered_url(loc, method="GET", actor=actor, current_url=url)

        if not body or status >= 500:
            return

        is_collection_2xx = (200 <= status < 300) and ("{id}" not in tmpl) and norm_p != "/"
        col_prefix = f"{norm_p}/"

        # Passive extraction from JSON / OpenAPI / HTML / JS / robots / sitemap
        stripped = body.lstrip()
        if "json" in ctype or stripped.startswith(("{", "[")):
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                    self._ingest_openapi_spec(parsed)
                hypermedia, _ = extract_json_hypermedia(parsed, url, origin_url=self.base_url)
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
                for spec_u in find_spec_urls(body, url):
                    self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if is_html_resp or "href=" in body.lower():
            for rec in extract_html(body, url):
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
            for script in extract_inline_scripts(body):
                for jc in extract_js_calls(script, url, limit=40):
                    self._register_discovered_url(
                        str(jc.get("url") or ""),
                        method=str(jc.get("method") or "GET"),
                        params=jc.get("params") or (),
                        actor=actor,
                        current_url=url,
                    )
                for sr in extract_spa_routes(script, url, limit=40):
                    self._register_discovered_url(
                        str(sr.get("url") or ""),
                        method="GET",
                        actor=actor,
                        current_url=url,
                    )
                for spec_u in find_spec_urls(script, url):
                    self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if "javascript" in ctype or norm_p.lower().endswith((".js", ".mjs")):
            for jc in extract_js_calls(body, url, limit=80):
                self._register_discovered_url(
                    str(jc.get("url") or ""),
                    method=str(jc.get("method") or "GET"),
                    params=jc.get("params") or (),
                    actor=actor,
                    current_url=url,
                )
            kept_js = 0
            for rec in extract_js(body, url, limit=240):
                cand_u = str(rec.get("url") or "")
                if is_non_endpoint_source_path(cand_u):
                    continue
                self._register_discovered_url(
                    cand_u,
                    method=str(rec.get("method") or "GET"),
                    params=rec.get("params") or (),
                    actor=actor,
                    current_url=url,
                )
                kept_js += 1
                if kept_js >= 60:
                    break
            kept_spa = 0
            for sr in extract_spa_routes(body, url, limit=160):
                cand_u = str(sr.get("url") or "")
                if is_non_endpoint_source_path(cand_u):
                    continue
                self._register_discovered_url(
                    cand_u,
                    method="GET",
                    actor=actor,
                    current_url=url,
                )
                kept_spa += 1
                if kept_spa >= 60:
                    break
            for spec_u in find_spec_urls(body, url):
                self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if norm_p.lower().endswith("/robots.txt"):
            for rec in extract_robots(body, url):
                self._register_discovered_url(str(rec.get("url") or ""), method="GET", actor=actor, current_url=url)
        if "xml" in ctype or "<urlset" in body[:512].lower() or "<sitemapindex" in body[:512].lower():
            for rec in extract_sitemap(body, url):
                self._register_discovered_url(str(rec.get("url") or ""), method="GET", actor=actor, current_url=url)

    def _ingest_openapi_spec(self, spec: dict[str, Any]) -> None:
        resolver = LocalSchema(spec)
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return
        for raw_path, path_item in paths.items():
            if not isinstance(raw_path, str) or not isinstance(path_item, dict):
                continue
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
                    raw_path,
                    method=m_up,
                    params=q_params,
                    current_url=self.base_url,
                )

    def ingest_surface(self, surface: dict[str, Any], *, actor: str = "") -> None:
        """Ingest structured output of `extract_surface` tool into the frontier tracker."""
        if not isinstance(surface, dict):
            return
        curr_url = str(surface.get("url") or self.base_url)
        for item in (surface.get("forms") or []):
            if isinstance(item, dict):
                self._register_discovered_url(
                    str(item.get("url") or ""),
                    method=str(item.get("method") or "GET"),
                    params=item.get("params") or (),
                    actor=actor,
                    current_url=curr_url,
                    is_form=True,
                )
        for item in [
            *(surface.get("links") or []),
            *(surface.get("js_calls") or []),
            *(surface.get("spa_routes") or []),
        ]:
            if isinstance(item, dict):
                self._register_discovered_url(
                    str(item.get("url") or ""),
                    method=str(item.get("method") or "GET"),
                    params=item.get("params") or (),
                    actor=actor,
                    current_url=curr_url,
                )
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
                    str(op.get("path") or op.get("url") or ""),
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

    def unvisited_routes(self) -> list[str]:
        """Return discovered routes and parameterized endpoints not yet tested."""
        out: list[str] = []
        seen_templates_in_out: set[tuple[str, str]] = set()
        for (method, norm_p), display in sorted(self.discovered_routes.items()):
            if method not in self.allowed_methods:
                continue
            tmpl = route_template_of(norm_p)
            # Skip unexpanded OpenAPI template strings `{...}` if a concrete path for that template was visited
            if "{" in norm_p and (method, tmpl) in self.visited_method_templates:
                continue
            if (method, norm_p) not in self.visited_method_paths and (method, tmpl) not in self.visited_method_templates:
                if (method, tmpl) not in seen_templates_in_out:
                    seen_templates_in_out.add((method, tmpl))
                    out.append(f"{method} {display}")
            else:
                # Check if discovered query/form parameters on this route template remain completely untested
                disc_p = self.discovered_params.get(tmpl) or set()
                tested_p = self.tested_params_by_template.get(tmpl) or set()
                untested_p = sorted(disc_p - tested_p)
                if untested_p and (method, tmpl) not in seen_templates_in_out:
                    seen_templates_in_out.add((method, tmpl))
                    param_hint = "&".join(f"{k}=" for k in untested_p[:4])
                    out.append(f"{method} {norm_p}?{param_hint}")
        return out

    def unprobed_params(self) -> list[str]:
        """Return discovered query params on visited routes that only received a single plain alphanumeric value."""
        out: list[str] = []
        visited_tmpls = {tmpl for _, tmpl in self.visited_method_templates}
        sample_path_by_tmpl: dict[str, str] = {}
        for _, path in sorted(self.visited_method_paths):
            t = route_template_of(path)
            if t not in sample_path_by_tmpl:
                sample_path_by_tmpl[t] = path

        for tmpl, disc_p in sorted(self.discovered_params.items()):
            if tmpl not in visited_tmpls or _is_auth_utility_path(tmpl):
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
                tmpl = route_template_of(norm_p)
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
                tmpl = route_template_of(norm_p)
                if "{id}" in tmpl or not norm_p.startswith("/api/") or _is_auth_utility_path(norm_p):
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
                0 if kv[0].startswith("/api/") else 1,
                kv[0],
            ),
        )
        for norm_p, info in ordered_objects:
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
            if _is_auth_utility_path(sample_path) or _is_auth_utility_path(tmpl):
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
        prefixes = self._ranked_api_prefixes()
        if not prefixes:
            return []
        primary_prefix = prefixes[0]
        probe_method = "GET" if "GET" in self.allowed_methods else next(iter(sorted(self.allowed_methods)), "GET")

        candidates: list[tuple[tuple[int, int, int, str], str]] = []
        for resource, info in self.ui_resource_families.items():
            if self._has_visited_api_resource(resource):
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

    def format_frontier_banner(self, *, max_chars: int = 1000) -> str:
        """Render a compact (~1 KB) `[SURFACE FRONTIER]` block for turn state injection."""
        if max_chars <= 0:
            return ""
        frontier = self.high_value_frontier()
        all_routes = self.unvisited_routes()
        all_params = self.unprobed_params()
        all_objs = self.untested_cross_actor_objects()
        all_writes = self.untested_write_ops()

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
            return "\n[SURFACE FRONTIER] All discovered routes, objects, and allowed write ops covered."[:max_chars]

        def _build(r_cap: int, q_cap: int, o_cap: int, p_cap: int, w_cap: int, a_cap: int) -> str:
            parts: list[str] = []
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

        for caps in ((6, 3, 4, 3, 6, 5), (3, 2, 2, 3, 3, 3), (2, 1, 1, 3, 1, 2), (1, 1, 1, 2, 1, 1)):
            candidate = _build(*caps)
            if len(candidate) <= max_chars:
                return candidate
        return _build(1, 1, 1, 2, 1, 1)[:max_chars]

    def to_dict(self) -> dict[str, Any]:
        """Serialize tracker state for checkpoint persistence."""
        return {
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
            "actors_by_template": {k: sorted(v) for k, v in self.actors_by_template.items()},
            "actors_by_path": {k: sorted(v) for k, v in self.actors_by_path.items()},
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
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        """Restore tracker state from a checkpoint dictionary."""
        if not isinstance(data, dict):
            return
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
        self.actors_by_template = {
            str(k): set(v) for k, v in (data.get("actors_by_template") or {}).items() if isinstance(v, list)
        }
        self.actors_by_path = {
            str(k): set(v) for k, v in (data.get("actors_by_path") or {}).items() if isinstance(v, list)
        }
        self.discovered_routes = {
            (str(x[0]), str(x[1])): str(x[2])
            for x in (data.get("discovered_routes") or [])
            if isinstance(x, list) and len(x) == 3
        }
        self.discovered_params = {
            str(k): set(v) for k, v in (data.get("discovered_params") or {}).items() if isinstance(v, list)
        }
        self.discovered_objects = {}
        for k, v in (data.get("discovered_objects") or {}).items():
            if isinstance(v, dict):
                self.discovered_objects[str(k)] = {
                    "path": str(v.get("path") or k),
                    "template": str(v.get("template") or route_template_of(str(k))),
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
        }
        self._pruned_404_objects = {str(x) for x in (data.get("pruned_404_objects") or [])}
        self.discovered_write_ops = {
            (str(x[0]), str(x[1])): str(x[2])
            for x in (data.get("discovered_write_ops") or [])
            if isinstance(x, list) and len(x) == 3
        }
        self.declared_write_ops = {
            (str(x[0]), str(x[1]))
            for x in (data.get("declared_write_ops") or [])
            if isinstance(x, list) and len(x) == 2
        }
        self.tested_write_ops = {(str(x[0]), str(x[1])) for x in (data.get("tested_write_ops") or []) if len(x) == 2}

        if isinstance(data.get("api_prefix_routes"), dict):
            self.api_prefix_routes = {
                str(k): {str(p) for p in v}
                for k, v in data["api_prefix_routes"].items()
                if isinstance(v, list)
            }
        else:
            self.api_prefix_routes = {}
            for _, path in list(self.discovered_routes.keys()) + list(self.visited_method_paths):
                prefix = _extract_api_prefix(path)
                if prefix:
                    self.api_prefix_routes.setdefault(prefix, set()).add(normalize_path(path))

        if isinstance(data.get("ui_resource_families"), dict):
            self.ui_resource_families = {}
            for k, v in data["ui_resource_families"].items():
                if isinstance(v, dict):
                    self.ui_resource_families[str(k)] = {
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

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any],
        *,
        base_url: str = "",
        allowed_methods: Sequence[str] | None = None,
        actor_summaries: Sequence[dict[str, str]] | None = None,
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
        tracker = cls(
            base_url=eff_base,
            allowed_methods=eff_methods,
            actor_summaries=eff_actors,
        )
        tracker.load_dict(raw)
        return tracker
