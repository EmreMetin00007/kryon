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
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any, Sequence
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
    _parse_cookie_pairs,
    _redact_secrets,
    _resolve_and_check_scope,
    _run_sync,
)
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
    _fit_body_template_budget,
    _sanitize_json_template,
    is_id_segment,
    is_non_endpoint_source_path,
    is_virgin_state_sensitive_path,
    route_template_of,
)
from target_bootstrap import normalize_path  # noqa: E402
from tech_routes import detect_tech  # noqa: E402

try:
    from kryon_core.surface.openapi import LocalSchema  # noqa: E402
except Exception:  # pragma: no cover - optional fallback
    LocalSchema = None  # type: ignore[assignment,misc]

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

_STANDARD_MANIFEST_PROBES: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/robots.txt",
    "/sitemap.xml",
    "/info",
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

_MAX_JS_CHUNKS = 96
_MAX_JS_CHUNK_BYTES = 256 * 1024
_MAX_STAGE0_SCRIPT_ASSETS = 160
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
  return {
    url: String(window.location.href || ''),
    base_uri: String(document.baseURI || window.location.href || ''),
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
    params: set[str] = field(default_factory=set)
    is_form: bool = False
    best_status: int = 0
    body_template: dict[str, Any] | None = None
    body_template_observed: bool = False
    multipart_fields: set[str] = field(default_factory=set)
    multipart_files: set[str] = field(default_factory=set)
    first_seen: int = 0


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
        "passive_probes_sent": 0,
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
        "discovery_hints": [],
        "seed_file": "",
        "stats": stats,
    }


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
        return bool(cookie_hdr or extra_hdrs or local_storage)

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


def _extract_openapi_templates(
    spec: dict[str, Any],
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], dict[str, list[str]]],
    list[tuple[str, str, list[str]]],
]:
    """Synthesize JSON body templates and multipart schemas from an OpenAPI/Swagger spec."""
    if not isinstance(spec, dict) or not isinstance(spec.get("paths"), dict):
        return {}, {}, []
    resolver = LocalSchema(spec) if LocalSchema is not None else None
    templates: dict[tuple[str, str], dict[str, Any]] = {}
    multipart_map: dict[tuple[str, str], dict[str, list[str]]] = {}
    ops_meta: list[tuple[str, str, list[str]]] = []

    for raw_path, path_item in spec["paths"].items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        if not raw_path.startswith("/"):
            continue
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
                                    templates[(method, raw_path)] = fitted
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
                                    templates[(method, raw_path)] = fitted
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
                                multipart_map[(method, raw_path)] = {
                                    "fields": sorted(set(mp_fields)),
                                    "files": sorted(set(mp_files)),
                                }
                                op_params.extend(mp_fields)
                                op_params.extend(mp_files)

            ops_meta.append((method, raw_path, list(dict.fromkeys(op_params))[:_MAX_PARAMS_PER_ROUTE]))
            if len(ops_meta) >= 120:
                return templates, multipart_map, ops_meta

    return templates, multipart_map, ops_meta


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

    def _hint_key(item: dict[str, Any]) -> tuple[int, int, str]:
        p = str(item.get("url") or "/")
        segs = [s for s in p.split("/") if s]
        has_id = 1 if any(is_id_segment(s) for s in segs) else 0
        score = _route_priority_score(
            method="GET",
            path=p,
            params=item.get("params") or (),
            is_form=bool(item.get("is_form")),
            status=int(item.get("status") or 0),
            has_body_template=bool(item.get("body_template")),
            has_multipart_schema=bool(item.get("multipart_schema")),
        )
        return (has_id, -score, p)

    ranked = sorted(get_routes, key=_hint_key)
    selected: list[str] = []
    seen_paths: set[str] = set()
    seen_templates: set[str] = set()

    for item in ranked:
        if len(selected) >= cap:
            return selected
        p = str(item.get("url") or "")
        tmpl = route_template_of(p)
        if not p or p in seen_paths or tmpl in seen_templates:
            continue
        seen_paths.add(p)
        seen_templates.add(tmpl)
        selected.append(p)

    for item in ranked:
        if len(selected) >= cap:
            break
        p = str(item.get("url") or "")
        if not p or p in seen_paths:
            continue
        seen_paths.add(p)
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
        self.routes: dict[tuple[str, str], _RouteRecord] = {}
        self.ws_endpoints: dict[tuple[str, str], dict[str, str]] = {}
        self.captured_html: dict[str, dict[str, Any]] = {}
        self.captured_js: dict[str, dict[str, Any]] = {}
        self.captured_css: dict[str, dict[str, Any]] = {}
        self.discovered_spec_urls: list[str] = []
        self.fetched_2xx_paths: set[str] = set()
        self.server_headers: list[str] = []
        self.powered_by_headers: list[str] = []
        self.body_snippets: list[str] = []
        self.script_assets_seen: set[str] = set()
        self.script_assets_requests = 0
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
        self.passive_probes_sent = 0

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

        path_params = _extract_path_embedded_params(norm_p)
        if (
            has_double_slash_path(raw_path)
            or (is_static_asset_url(norm_p) and not path_params)
            or is_non_endpoint_source_path(norm_p)
            or _is_stage0_noise_path(norm_p, origin_url=self.http.base_url)
        ):
            return False

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

        key = (norm_method, norm_p)
        with self._lock:
            rec = self.routes.get(key)
            if rec is None:
                self._seen_order += 1
                rec = _RouteRecord(
                    method=norm_method,
                    path=norm_p,
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
                self.fetched_2xx_paths.add(norm_p)
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
    ) -> None:
        if not body:
            return
        with self._lock:
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
            }
            if is_css:
                store, store_key, cap = self.captured_css, norm_p, _MAX_CSS_DOCS
            elif is_js:
                store, store_key, cap = self.captured_js, norm_p, _MAX_JS_CHUNKS
            else:
                doc_key = f"{norm_p}?{parsed.query}" if parsed.query else norm_p
                store, store_key, cap = self.captured_html, doc_key, _MAX_HTML_DOCS
            if store_key not in store and len(store) < cap:
                store[store_key] = entry

    def ingest_surface_summary(self, summary: dict[str, Any], *, source_url: str) -> None:
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
            self.record_route(
                method=str(op.get("method") or "GET"),
                raw_url=str(op.get("path") or op.get("url") or ""),
                current_url=self.http.base_url,
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
                _u, sp_path, _q = _check_http_scope(self.http, spec_u, allow_fragment=False)
                norm_sp = normalize_path(sp_path)
            except (ScopeViolationError, ValueError):
                continue
            if not _is_skipped_surface_url(norm_sp):
                with self._lock:
                    if norm_sp not in self.discovered_spec_urls and len(self.discovered_spec_urls) < 12:
                        self.discovered_spec_urls.append(norm_sp)


def _fill_and_submit_form(
    page: Any,
    form_info: dict[str, Any],
    *,
    timeout_ms: int,
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
) -> list[str]:
    """Run Layers 1-3 inside an isolated Playwright context for a single actor."""
    cookie_hdr, extra_headers = _extract_actor_browser_auth(http_client, actor)
    local_storage = _extract_actor_local_storage(http_client, actor)
    actor_secrets = _collect_actor_secrets(
        http_client,
        cookie_hdr,
        extra_headers,
        local_storage=local_storage,
    )

    context = browser.new_context(
        ignore_https_errors=True,
        service_workers="block",
        user_agent=_BROWSER_USER_AGENT,
    )
    session_dropped = False
    form_submitting_flag = [False]

    try:
        ls_init_script = _build_origin_localstorage_init_script(http_client.base_url, local_storage)
        if ls_init_script:
            context.add_init_script(ls_init_script)

        cookie_pairs = _parse_cookie_pairs(cookie_hdr)
        if cookie_pairs:
            context.add_cookies([
                {"name": cname, "value": cval, "url": http_client.base_url}
                for cname, cval in cookie_pairs
            ])

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

        def _continue_route(route: Any, req: Any, *, include_extra_headers: bool) -> None:
            if include_extra_headers and extra_headers:
                try:
                    raw_hdrs = dict(req.all_headers() or {})
                except Exception:
                    raw_hdrs = dict(getattr(req, "headers", None) or {})
                merged = {
                    str(k): str(v)
                    for k, v in raw_hdrs.items()
                    if k and not str(k).startswith(":")
                }
                existing_lower = {k.lower() for k in merged}
                for hk, hv in extra_headers.items():
                    if hk.lower() not in existing_lower:
                        merged[hk] = hv
                try:
                    route.continue_(headers=merged)
                except Exception:
                    pass
                return
            try:
                route.continue_()
            except Exception:
                pass

        def _on_route(route: Any) -> None:
            req = route.request
            req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
            req_url = str(getattr(req, "url", "") or "")
            try:
                _clean, req_path, _q = _check_http_scope(http_client, req_url, allow_fragment=False)
            except ScopeViolationError:
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
            try:
                _clean, resp_path, _q = _check_http_scope(http_client, resp_url, allow_fragment=False)
            except ScopeViolationError:
                return

            status = int(getattr(resp, "status", 0) or 0)
            req_obj = getattr(resp, "request", None)
            req_method = str(getattr(req_obj, "method", "GET") or "GET").strip().upper()
            try:
                resp_headers = {str(k): str(v) for k, v in (getattr(resp, "headers", None) or {}).items()}
            except Exception:
                resp_headers = {}
            ctype = str(resp_headers.get("content-type") or resp_headers.get("Content-Type") or "").lower()
            loc_hdr = str(resp_headers.get("location") or resp_headers.get("Location") or "")

            # Session-drop guard for authenticated form crawling.
            if actor != "anon" and forms_enabled and form_submitting_flag[0]:
                if status == 401 or (
                    300 <= status < 400 and loc_hdr and _AUTH_FORM_RE.search(urlsplit(loc_hdr).path or "")
                ):
                    session_dropped = True

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
            if not is_js and not is_css and not is_html:
                return
            max_bytes = _MAX_JS_CHUNK_BYTES if is_js else (_MAX_CSS_BYTES if is_css else _MAX_HTML_BYTES)
            try:
                raw_body = resp.body()
            except Exception:
                return
            if not raw_body:
                return
            text_body = bytes(raw_body[:max_bytes]).decode("utf-8", errors="replace")
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
        queued_urls: set[str] = set()
        visited_urls: set[str] = set()
        template_visit_counts: dict[tuple[str, frozenset[str], str], int] = {}
        seen_dom_states: set[tuple[str, str, str]] = set()
        submitted_forms: set[tuple[Any, ...]] = set()
        actor_pages_visited = 0
        actor_actions_taken = 0

        def _enqueue_url(raw_candidate: str, current_page_url: str) -> None:
            cand = str(raw_candidate or "").strip()
            if not cand or cand.lower().startswith(_NON_HTTP_SCHEMES):
                return
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
            ):
                return
            if actor != "anon" and _DESTRUCTIVE_RE.search(norm_p):
                return
            if full_u in queued_urls or full_u in visited_urls:
                return
            frag = urlsplit(full_u).fragment
            q_keys = frozenset(k for k, _ in parse_qsl(query_u, keep_blank_values=True) if k)
            tmpl_key = (route_template_of(norm_p), q_keys, _normalize_hash_route(f"#{frag}" if frag else ""))
            if template_visit_counts.get(tmpl_key, 0) >= _MAX_VISITS_PER_TEMPLATE:
                return
            queued_urls.add(full_u)
            queue.append(full_u)

        for start_u in start_urls:
            _enqueue_url(start_u, http_client.base_url)

        def _dom_link_base(dom_data: dict[str, Any], current_page_url: str) -> str:
            raw_base_uri = str(dom_data.get("base_uri") or "").strip()
            if not raw_base_uri:
                return current_page_url
            try:
                clean_b, _bp, _bq = _check_http_scope(http_client, raw_base_uri, allow_fragment=False)
                return clean_b
            except ScopeViolationError:
                return current_page_url

        def _ingest_dom_discovery(dom_data: dict[str, Any], current_page_url: str) -> None:
            link_base = _dom_link_base(dom_data, current_page_url)
            for link_raw in dom_data.get("links") or ():
                collector.record_route(method="GET", raw_url=str(link_raw), current_url=link_base)
                _enqueue_url(str(link_raw), link_base)
            for h_raw in dom_data.get("hash_routes") or ():
                _enqueue_url(str(h_raw), current_page_url)
            for form_item in dom_data.get("forms") or ():
                if not isinstance(form_item, dict):
                    continue
                raw_action = str(form_item.get("action") or "").strip()
                f_action = raw_action or current_page_url
                f_base = link_base if raw_action else current_page_url
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
                resolved_action = urljoin(link_base, raw_action) if raw_action else current_page_url
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
                    submitted, uploaded = _fill_and_submit_form(page, form_item, timeout_ms=timeout_ms)
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

        while queue and actor_pages_visited < actor_page_limit and stage0_budget.can_spend():
            target_url = queue.popleft()
            if target_url in visited_urls:
                continue
            parsed_t = urlsplit(target_url)
            try:
                norm_t_path = normalize_path(parsed_t.path or "/")
            except ValueError:
                continue
            q_keys = frozenset(k for k, _ in parse_qsl(parsed_t.query, keep_blank_values=True) if k)
            tmpl_key = (route_template_of(norm_t_path), q_keys, _normalize_hash_route(f"#{parsed_t.fragment}" if parsed_t.fragment else ""))
            if template_visit_counts.get(tmpl_key, 0) >= _MAX_VISITS_PER_TEMPLATE:
                continue

            visited_urls.add(target_url)
            template_visit_counts[tmpl_key] = template_visit_counts.get(tmpl_key, 0) + 1
            actor_pages_visited += 1
            collector.pages_visited += 1

            try:
                page.goto(target_url, wait_until="domcontentloaded", timeout=timeout_ms)
                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)
            except Exception:
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

            try:
                canon_path = normalize_path(urlsplit(final_url).path or "/")
            except ValueError:
                canon_path = "/"
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


def _run_layer4_passive_fusion(
    http_client: AgenticHTTPClient,
    collector: _Stage0Collector,
    stage0_budget: _Stage0Budget,
    *,
    primary_actor: str,
    max_passive_probes: int,
) -> None:
    """Fuse captured HTML, JS chunks, and CSS via ``_extract_surface_summary`` and run bounded manifest probes."""
    idx = 0
    for docs, prefix, default_ctype, is_js_batch in (
        (list(collector.captured_html.values()), "html", "text/html", False),
        (list(collector.captured_js.values())[:_MAX_JS_CHUNKS], "js", "application/javascript", True),
        (list(collector.captured_css.values())[:_MAX_CSS_DOCS], "css", "text/css", False),
    ):
        for doc in docs:
            idx += 1
            if is_js_batch:
                collector.js_chunks_parsed += 1
            fake_rec = {
                "receipt_id": f"stage0-{prefix}-{idx}",
                "url": doc["url"],
                "content_type": doc["content_type"] or default_ctype,
                "body": doc["body"],
                "response_headers": doc["headers"],
                "redirect_location": "",
            }
            try:
                summary = _extract_surface_summary(fake_rec, http_client.base_url)
                collector.ingest_surface_summary(summary, source_url=doc["url"])
            except Exception:
                continue

    if max_passive_probes <= 0 or "GET" not in http_client.allowed_methods:
        return

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

    probe_candidates: list[str] = []
    seen_probes: set[str] = set()
    for raw_p in [*collector.discovered_spec_urls, *_STANDARD_MANIFEST_PROBES, *tech_probes]:
        try:
            _u, clean_p, _q = _check_http_scope(http_client, raw_p, allow_fragment=False)
            norm_p = normalize_path(clean_p)
        except (ScopeViolationError, ValueError):
            continue
        low_p = norm_p.lower()
        if any(sens in low_p for sens in _SENSITIVE_PROBE_SEGMENTS):
            continue
        if norm_p in seen_probes or norm_p in collector.fetched_2xx_paths:
            continue
        seen_probes.add(norm_p)
        probe_candidates.append(norm_p)

    for probe_path in probe_candidates:
        if collector.passive_probes_sent >= max_passive_probes:
            break
        if not stage0_budget.can_spend(include_reserve=True):
            break
        before_used = int(http_client.budget.used)
        try:
            rec = http_client.request(actor=primary_actor, method="GET", url=probe_path)
        except BudgetExhaustedError:
            stage0_budget.global_exhausted = True
            break
        except ServiceDegradationError:
            break
        except (ScopeViolationError, MethodNotAllowedError):
            continue
        except Exception:
            after_used = int(http_client.budget.used)
            stage0_budget.account_external(max(0, after_used - before_used))
            continue

        after_used = int(http_client.budget.used)
        stage0_budget.account_external(max(0, after_used - before_used))
        collector.passive_probes_sent += 1

        status = int(rec.get("status") or 0)
        if not (200 <= status < 300):
            continue

        rec_url = str(rec.get("url") or urljoin(http_client.base_url, probe_path))
        collector.record_route(method="GET", raw_url=rec_url, status=status)
        try:
            summary = _extract_surface_summary(rec, http_client.base_url)
            collector.ingest_surface_summary(summary, source_url=rec_url)
        except Exception:
            pass

        body_text = str(rec.get("body") or "")
        stripped = body_text.lstrip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(body_text)
            except ValueError:
                parsed = None
            if isinstance(parsed, dict) and "paths" in parsed and ("openapi" in parsed or "swagger" in parsed):
                oa_templates, oa_multipart, oa_ops = _extract_openapi_templates(parsed)
                for op_method, op_path, op_params in oa_ops:
                    collector.record_route(
                        method=op_method,
                        raw_url=op_path,
                        current_url=http_client.base_url,
                        params=op_params,
                        body_template=oa_templates.get((op_method, op_path)),
                        body_template_observed=False,
                        multipart_schema=oa_multipart.get((op_method, op_path)),
                    )


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
        tmpl = route_template_of(rec.path)
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
                r.path,
            ),
        )
        for rep in ranked_members[:_MAX_REPS_PER_CLUSTER]:
            entry: dict[str, Any] = {
                "method": method,
                "url": rep.path,
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
            clustered_items.append((-score, rep.first_seen, rep.path, method, entry))

    clustered_items.sort(key=lambda row: (row[0], row[1], row[2], row[3]))
    kept_entries = [row[4] for row in clustered_items[:_MAX_ROUTES_RETURNED]]

    links: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    for entry in kept_entries:
        if entry.get("is_form"):
            forms.append(entry)
        else:
            links.append(entry)

    discovery_hints = _select_discovery_hints(kept_entries, _MAX_DISCOVERY_HINTS)
    return links, forms, body_templates_map, multipart_schemas_map, discovery_hints


def run_stage0_crawl(
    http_client: AgenticHTTPClient,
    *,
    output_dir: Path | str | None = None,
    start_paths: Sequence[str] | None = None,
    max_pages: int = 12,
    max_actions: int = 24,
    allow_forms: bool = False,
    actors: Sequence[str] | None = None,
    seed_filename: str = "stage0-seed.json",
    timeout_ms: int = 12000,
    wait_ms: int = 500,
    max_passive_probes: int = 12,
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
    raw_starts = list(start_paths) if start_paths else ["/"]
    valid_starts: list[str] = []
    for raw_sp in raw_starts:
        try:
            full_s, _p, _q = _check_http_scope(http_client, str(raw_sp), allow_fragment=True)
            if full_s not in valid_starts:
                valid_starts.append(full_s)
        except ScopeViolationError:
            continue
    if not valid_starts:
        try:
            root_u, _p, _q = _check_http_scope(http_client, "/", allow_fragment=False)
            valid_starts = [root_u]
        except ScopeViolationError:
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
                    )
                    collected_secrets.update(secrets_for_actor)
                    actors_done.append(actor_alias)
            finally:
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
        )

    links, forms, body_templates_map, multipart_schemas_map, discovery_hints = _finalize_routes(collector)
    ws_endpoints = list(collector.ws_endpoints.values())
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
        "passive_probes_sent": int(collector.passive_probes_sent),
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
    "run_stage0_crawl",
    "should_skip_stage0_form_submit",
]
