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
_SURFACE_CORE_PARENT = _REPO_ROOT / "mcp-servers" / "mcp-memory-server"
if str(_SURFACE_CORE_PARENT) not in sys.path:
    sys.path.insert(0, str(_SURFACE_CORE_PARENT))

from cco_surface_core.extract import (  # noqa: E402
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
from cco_surface_core.openapi import LocalSchema  # noqa: E402

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
    norm_p = normalize_path(path)
    if norm_p == "/" or _extract_api_prefix(norm_p) or is_static_asset_url(norm_p):
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
        self.actors_by_template: dict[str, set[str]] = {}
        self.actors_by_path: dict[str, set[str]] = {}
        self.route_2xx_actors: dict[str, set[str]] = {}

        # Discovered attack surface
        # key: (method, normalized_path) -> sample URL or path with query hint
        self.discovered_routes: dict[tuple[str, str], str] = {}
        # key: route_template -> set of discovered query/form param names
        self.discovered_params: dict[str, set[str]] = {}
        # key: concrete_path -> {"path": str, "template": str, "owner_actor": str, "seen_by": set[str], "tested_by": set[str]}
        self.discovered_objects: dict[str, dict[str, Any]] = {}
        # key: (method, route_template) -> concrete or sample path
        self.discovered_write_ops: dict[tuple[str, str], str] = {}
        self.declared_write_ops: set[tuple[str, str]] = set()
        self.tested_write_ops: set[tuple[str, str]] = set()
        # Observed API prefixes and non-API UI resource families for UI <-> API parity
        self.api_prefix_routes: dict[str, set[str]] = {}
        self.ui_resource_families: dict[str, dict[str, Any]] = {}

    def _observe_parity_path(
        self,
        norm_p: str,
        *,
        discovered: bool,
        status: int = 0,
        ctype: str = "",
    ) -> None:
        api_prefix = _extract_api_prefix(norm_p)
        if api_prefix:
            if discovered or status != 404:
                self.api_prefix_routes.setdefault(api_prefix, set()).add(norm_p)
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

    def _resolve_same_origin(self, raw_url: str, current_url: str = "") -> tuple[str, str] | None:
        raw = str(raw_url or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "//")):
            return None
        base_ref = urljoin(self.base_url, current_url) if current_url else self.base_url
        resolved = urljoin(base_ref, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != self._origin:
            return None
        if is_static_asset_url(parsed.path):
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
            self._register_object_path(norm_p, actor=actor, visited=False)

        self._observe_parity_path(norm_p, discovered=True)

    def _register_object_path(
        self,
        concrete_path: str,
        *,
        actor: str = "",
        owner_hint: str = "",
        visited: bool = False,
        verified_2xx: bool = False,
    ) -> None:
        norm_p = normalize_path(concrete_path)
        tmpl = route_template_of(norm_p)
        if "{id}" not in tmpl or "{" in norm_p or norm_p.lower().endswith((".js", ".mjs")):
            return
        entry = self.discovered_objects.get(norm_p)
        clean_actor = str(actor or "").strip()
        clean_owner = str(owner_hint or "").strip()
        if entry is None:
            owner = clean_owner if clean_owner in self.actors and clean_owner != "anon" else (
                clean_actor if clean_actor in self.actors and clean_actor != "anon" else ""
            )
            entry = {
                "path": norm_p,
                "template": tmpl,
                "owner_actor": owner,
                "seen_by": {clean_actor} if clean_actor else set(),
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
            items = [x for x in parsed_json[:20] if isinstance(x, dict)]
        elif isinstance(parsed_json, dict):
            for v in parsed_json.values():
                if isinstance(v, list):
                    items.extend(x for x in v[:20] if isinstance(x, dict))

        for obj in items[:15]:
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
                        self._register_object_path(obj_path, actor=actor, owner_hint=owner_val, visited=False)
                        if "GET" in self.allowed_methods:
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
        q_keys = {k.strip() for k, _ in parse_qsl(query_str, keep_blank_values=True) if k.strip()}
        if q_keys:
            self.tested_params_by_template.setdefault(tmpl, set()).update(q_keys)

        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            req_body = str(receipt.get("request_body") or "")
            for k, _ in parse_qsl(req_body, keep_blank_values=True):
                if k.strip():
                    self.tested_params_by_template.setdefault(tmpl, set()).add(k.strip())
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
            else:
                obj_entry["tested_by"].add(actor)

        # Follow same-origin redirect Location
        loc = str(receipt.get("redirect_location") or "").strip()
        if loc:
            self._register_discovered_url(loc, method="GET", actor=actor, current_url=url)

        if not body or status >= 500:
            return

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
                    self._register_discovered_url(
                        str(item.get("url") or ""),
                        method=str(item.get("method") or "GET"),
                        params=item.get("params") or (),
                        actor=actor,
                        current_url=url,
                    )
                if 200 <= status < 300:
                    self._extract_collection_item_paths(norm_p, parsed, actor)
                for spec_u in find_spec_urls(body, url):
                    self._register_discovered_url(spec_u, method="GET", actor=actor, current_url=url)

        if "html" in ctype or "<html" in body[:512].lower() or "<form" in body.lower() or "href=" in body.lower():
            for rec in extract_html(body, url):
                self._register_discovered_url(
                    str(rec.get("url") or ""),
                    method=str(rec.get("method") or "GET"),
                    params=rec.get("params") or (),
                    actor=actor,
                    current_url=url,
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
            for rec in extract_js(body, url, limit=60):
                self._register_discovered_url(
                    str(rec.get("url") or ""),
                    method=str(rec.get("method") or "GET"),
                    params=rec.get("params") or (),
                    actor=actor,
                    current_url=url,
                )
            for sr in extract_spa_routes(body, url, limit=60):
                self._register_discovered_url(
                    str(sr.get("url") or ""),
                    method="GET",
                    actor=actor,
                    current_url=url,
                )
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
        for item in [
            *(surface.get("links") or []),
            *(surface.get("forms") or []),
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

        # 3. Concrete object endpoints ({id}) for BOLA (same-tenant peer) & Tenant Isolation (cross-tenant actor)
        templates_cross_tested: set[str] = set()
        for norm_p, info in self.discovered_objects.items():
            tmpl = info["template"]
            tested_non_anon = {a for a in info["tested_by"] if a != "anon"}
            owner = info.get("owner_actor") or ""
            if owner and any(a != owner for a in tested_non_anon):
                rec_peers = self._recommended_cross_actors(owner)
                if all(p in (self.actors_by_template.get(tmpl) or set()) for p in rec_peers):
                    templates_cross_tested.add(tmpl)

        seen_tmpl_owner: set[tuple[str, str]] = set()
        for norm_p, info in sorted(self.discovered_objects.items()):
            tmpl = info["template"]
            if tmpl in templates_cross_tested:
                continue
            owner = info.get("owner_actor") or next(iter(info["seen_by"]), "")
            tested_by = info["tested_by"]
            rec_actors = [a for a in self._recommended_cross_actors(owner) if a not in tested_by]
            if not tested_by:
                target_actor = owner or next((a for a in self.actors if a != "anon"), "anon")
                if (tmpl, target_actor) not in seen_tmpl_owner:
                    seen_tmpl_owner.add((tmpl, target_actor))
                    out.append(f"GET {norm_p} (unfetched object; test as {target_actor} then replay_as peer)")
            elif rec_actors:
                if (tmpl, owner) not in seen_tmpl_owner:
                    seen_tmpl_owner.add((tmpl, owner))
                    peers_str = ",".join(rec_actors[:2])
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
            "untested_cross_actor_objects": self.untested_cross_actor_objects()[:8],
            "untested_write_ops": self.untested_write_ops()[:8],
            "api_parity_untested": self.untested_api_parity()[:6],
            "untested_actors": self.untested_actors()[:6],
        }

    def has_high_value_frontier(self) -> bool:
        """Return True if any high-value route, cross-actor object, write op, or API parity item remains untested."""
        frontier = self.high_value_frontier()
        return bool(
            frontier["unvisited_routes"]
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
        all_objs = self.untested_cross_actor_objects()
        all_writes = self.untested_write_ops()

        if not any(
            (
                frontier["unvisited_routes"],
                frontier["untested_cross_actor_objects"],
                frontier["untested_write_ops"],
                frontier["api_parity_untested"],
                frontier["untested_actors"],
            )
        ):
            return "\n[SURFACE FRONTIER] All discovered routes, objects, and allowed write ops covered."[:max_chars]

        def _build(r_cap: int, o_cap: int, p_cap: int, w_cap: int, a_cap: int) -> str:
            parts: list[str] = []
            if frontier["unvisited_routes"]:
                routes = ", ".join(frontier["unvisited_routes"][:r_cap])
                parts.append(f"unvisited_routes({len(all_routes)}): [{routes}]")
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

        for caps in ((6, 4, 3, 6, 5), (3, 2, 3, 3, 3), (2, 1, 3, 1, 2), (1, 1, 2, 1, 1)):
            candidate = _build(*caps)
            if len(candidate) <= max_chars:
                return candidate
        return _build(1, 1, 2, 1, 1)[:max_chars]

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
                    "tested_by": sorted(v["tested_by"]),
                }
                for k, v in self.discovered_objects.items()
            },
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
                    "tested_by": set(v.get("tested_by") or []),
                }
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
