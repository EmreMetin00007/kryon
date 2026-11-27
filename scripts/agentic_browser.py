"""Read-only, same-origin scope-locked headless Playwright integration for the agentic engine.

Provides two bounded capabilities:
1. ``run_browser_crawl``: SPA/Shadow-DOM surface discovery backed by ``kryon_core.surface.crawl``
   with strict same-origin filtering, WireBudget accounting, host-side actor auth injection,
   and automatic ingestion into ``SurfaceFrontierTracker``.
2. ``inspect_rendered_page``: Isolated read-only Chromium QA inspector for a single rendered
   page, capturing CSP headers, runtime fetch/XHR metadata via ``build_runtime_hook_script``,
   console error counts, and optional rendered-DOM marker placement checks.
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
import inspect
import json
from pathlib import Path
import sys
import threading
from typing import Any, Callable, Iterator, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit

from agentic_http import (
    AgenticHTTPClient,
    BudgetExhaustedError,
    ScopeViolationError,
    is_static_asset_url,
)
from agentic_surface import SurfaceFrontierTracker

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from kryon_core.surface.crawl import (  # noqa: E402
        CHROMIUM_ARGS as _CRAWL_CHROMIUM_ARGS,
        HAS_PLAYWRIGHT as _CRAWL_HAS_PLAYWRIGHT,
        crawl_site as _default_crawl_site,
        run_playwright_sync as _crawl_run_playwright_sync,
    )
except Exception:  # pragma: no cover - optional dependency fallback
    _CRAWL_CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]
    _CRAWL_HAS_PLAYWRIGHT = False
    _default_crawl_site = None  # type: ignore[assignment]
    _crawl_run_playwright_sync = None  # type: ignore[assignment]

try:
    from kryon_core.browser.hooks import (  # noqa: E402
        build_runtime_hook_script as _build_runtime_hook_script,
        normalize_dom_sinks as _normalize_dom_sinks,
        normalize_postmessage_listeners as _normalize_postmessage_listeners,
        normalize_runtime_events as _normalize_runtime_events,
    )
except Exception:  # pragma: no cover - optional dependency fallback
    _build_runtime_hook_script = None  # type: ignore[assignment]
    _normalize_dom_sinks = None  # type: ignore[assignment]
    _normalize_postmessage_listeners = None  # type: ignore[assignment]
    _normalize_runtime_events = None  # type: ignore[assignment]

try:
    from playwright.sync_api import sync_playwright as _sync_playwright  # type: ignore[import-not-found]

    _PW_IMPORT_OK = True
except Exception:  # pragma: no cover - optional dependency fallback
    _sync_playwright = None  # type: ignore[assignment]
    _PW_IMPORT_OK = False

CHROMIUM_ARGS: list[str] = list(_CRAWL_CHROMIUM_ARGS)
HAS_PLAYWRIGHT: bool = bool(_CRAWL_HAS_PLAYWRIGHT and _PW_IMPORT_OK)

_MAX_PAGES_UPPER = 12
_MAX_WAIT_MS = 2000
_MIN_TIMEOUT_MS = 1000
_MAX_TIMEOUT_MS = 30000

_MAX_RETURNED_PAGES = 12
_MAX_RETURNED_LINKS = 60
_MAX_RETURNED_FORMS = 30
_MAX_RETURNED_XHR = 40
_MAX_RETURNED_RUNTIME_REQUESTS = 40

_EXCLUDED_BROWSER_HEADERS = frozenset({
    "cookie",
    "host",
    "origin",
    "referer",
    "content-length",
    "connection",
    "transfer-encoding",
    "proxy-authorization",
    "user-agent",
})
_NON_HTTP_SCHEMES = ("javascript:", "mailto:", "data:", "blob:", "tel:", "about:")
_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/120.0.0.0 Safari/537.36"
)

_COLLECT_RUNTIME_JS = r"""() => {
  const rt = window.__ccoRuntime;
  if (!rt) return {events: [], state: {}, dom_sinks: [], postmessage_listeners: []};
  return {
    events: Array.isArray(rt.events) ? rt.events : [],
    state: typeof rt.snapshot === "function" ? rt.snapshot() : {},
    dom_sinks: Array.isArray(rt.dom_sinks) ? rt.dom_sinks : [],
    postmessage_listeners: Array.isArray(rt.postmessage_listeners) ? rt.postmessage_listeners : [],
  };
}"""

_CHECK_DOM_CANARY_JS = r"""(attrName) => {
  const targetAttr = String(attrName || "data-kryon-dom-canary");
  const walk = (root) => {
    if (!root || !root.querySelectorAll) return false;
    try {
      if (root.querySelector(`[${targetAttr}]`)) return true;
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot && walk(el.shadowRoot)) return true;
      }
    } catch (_) {}
    return false;
  };
  return walk(document);
}"""

_INSPECT_DOM_JS = r"""(marker) => {
  const title = String(document.title || "").slice(0, 180);
  const innerText = document.body ? String(document.body.innerText || "") : "";
  const outerHTML = document.documentElement ? String(document.documentElement.outerHTML || "") : "";
  if (!marker) {
    return {
      title,
      checked: false,
      in_inner_text: false,
      in_outer_html: false,
      in_script_or_event_attr: false,
      script_matches: 0,
      event_attr_matches: [],
    };
  }
  const inInnerText = innerText.includes(marker);
  const inOuterHtml = outerHTML.includes(marker);
  let scriptMatches = 0;
  const eventAttrMatches = [];
  const walk = (root) => {
    if (!root || !root.querySelectorAll) return;
    for (const sc of root.querySelectorAll("script")) {
      const txt = String(sc.textContent || "");
      const src = String(sc.getAttribute("src") || "");
      if (txt.includes(marker) || src.includes(marker)) {
        scriptMatches += 1;
      }
    }
    for (const el of root.querySelectorAll("*")) {
      if (el.attributes) {
        for (const attr of el.attributes) {
          const aname = String(attr.name || "").toLowerCase();
          const aval = String(attr.value || "");
          if (!aval.includes(marker)) continue;
          if (
            aname.startsWith("on")
            || (
              (aname === "href" || aname === "src" || aname === "action" || aname === "formaction")
              && /^\s*javascript:/i.test(aval)
            )
          ) {
            const tag = String(el.tagName || "").toLowerCase();
            const label = `${tag}[${aname}]`;
            if (!eventAttrMatches.includes(label) && eventAttrMatches.length < 20) {
              eventAttrMatches.push(label);
            }
          }
        }
      }
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);
  return {
    title,
    checked: true,
    in_inner_text: inInnerText,
    in_outer_html: inOuterHtml,
    in_script_or_event_attr: scriptMatches > 0 || eventAttrMatches.length > 0,
    script_matches: scriptMatches,
    event_attr_matches: eventAttrMatches,
  };
}"""


_CRAWL_CONTEXT_HOOK_LOCK = threading.Lock()


class _AttrProxy:
    """Lightweight proxy forwarding attribute access except explicit method/attribute overrides."""

    def __init__(self, target: Any, **overrides: Any) -> None:
        self._target = target
        self._overrides = overrides

    def __getattr__(self, name: str) -> Any:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._target, name)


class _SyncPwContextProxy:
    """Proxy for ``sync_playwright()`` injecting init scripts and cookies on every new BrowserContext."""

    def __init__(self, inner: Any, on_context: Callable[[Any], None]) -> None:
        self._inner = inner
        self._on_context = on_context

    def __enter__(self) -> Any:
        pw = self._inner.__enter__()
        orig_chromium = pw.chromium

        def _launch(*args: Any, **kwargs: Any) -> Any:
            browser = orig_chromium.launch(*args, **kwargs)
            orig_new_context = browser.new_context

            def _new_context(*nc_args: Any, **nc_kwargs: Any) -> Any:
                ctx = orig_new_context(*nc_args, **nc_kwargs)
                self._on_context(ctx)
                return ctx

            return _AttrProxy(browser, new_context=_new_context)

        chromium_proxy = _AttrProxy(orig_chromium, launch=_launch)
        return _AttrProxy(pw, chromium=chromium_proxy)

    def __exit__(self, *args: Any) -> Any:
        return self._inner.__exit__(*args)


@contextmanager
def _inject_crawl_browser_state(
    ls_init_script: str,
    cookie_records: Sequence[dict[str, Any]] = (),
) -> Iterator[None]:
    """Ensure ``kryon_core.surface.crawl.crawl_site`` receives init scripts and per-origin cookies."""
    if not ls_init_script and not cookie_records:
        yield
        return
    try:
        import kryon_core.surface.crawl as crawl_mod
    except Exception:
        yield
        return
    orig_sync_pw = getattr(crawl_mod, "sync_playwright", None)
    if orig_sync_pw is None:
        yield
        return

    def _on_context(ctx: Any) -> None:
        if ls_init_script:
            ctx.add_init_script(ls_init_script)
        if cookie_records:
            ctx.add_cookies(list(cookie_records))

    def _wrapped_sync_pw(*args: Any, **kwargs: Any) -> Any:
        return _SyncPwContextProxy(orig_sync_pw(*args, **kwargs), _on_context)

    with _CRAWL_CONTEXT_HOOK_LOCK:
        crawl_mod.sync_playwright = _wrapped_sync_pw
        try:
            yield
        finally:
            crawl_mod.sync_playwright = orig_sync_pw


def _run_sync(fn: Callable[[], dict[str, Any]], *, timeout: float = 120.0) -> dict[str, Any]:
    """Run synchronous Playwright work safely even if an asyncio loop is active."""
    if callable(_crawl_run_playwright_sync):
        return _crawl_run_playwright_sync(fn, timeout=timeout)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="agentic-pw") as pool:
        return pool.submit(fn).result(timeout=timeout)


def _parse_cookie_pairs(cookie_blob: str) -> list[tuple[str, str]]:
    """Parse a raw Cookie header string into ordered (name, value) pairs."""
    pairs: list[tuple[str, str]] = []
    index: dict[str, int] = {}
    for chunk in str(cookie_blob or "").split(";"):
        part = chunk.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        clean_name = name.strip()
        clean_val = value.strip()
        if not clean_name:
            continue
        if clean_name in index:
            pairs[index[clean_name]] = (clean_name, clean_val)
        else:
            index[clean_name] = len(pairs)
            pairs.append((clean_name, clean_val))
    return pairs


def _normalize_browser_auth_parts(
    *,
    cookie_blob: str = "",
    cookies_map: dict[str, Any] | None = None,
    base_headers: dict[str, Any] | None = None,
    access_token: str = "",
) -> tuple[str, dict[str, str]]:
    """Build host-side Playwright ``(cookie_header, extra_headers)`` from session state."""
    header_cookie_chunks: list[str] = []
    extra_headers: dict[str, str] = {}
    for raw_k, raw_v in (base_headers or {}).items():
        key = str(raw_k or "").strip()
        if not key or raw_v is None:
            continue
        val = str(raw_v)
        low = key.lower()
        if low == "cookie":
            if val.strip():
                header_cookie_chunks.append(val.strip())
            continue
        if low in _EXCLUDED_BROWSER_HEADERS:
            continue
        extra_headers[key] = val

    merged_cookies: dict[str, str] = {}
    for blob in [*header_cookie_chunks, str(cookie_blob or "").strip()]:
        for ck, cv in _parse_cookie_pairs(blob):
            merged_cookies[ck] = cv
    for ck, cv in sorted((cookies_map or {}).items(), key=lambda kv: str(kv[0])):
        clean_k = str(ck or "").strip()
        if clean_k and cv is not None:
            merged_cookies[clean_k] = str(cv)

    cookie_hdr = "; ".join(f"{k}={v}" for k, v in merged_cookies.items())
    if not cookie_hdr:
        fallback_blob = "; ".join(c for c in [*header_cookie_chunks, str(cookie_blob or "").strip()] if c)
        cookie_hdr = fallback_blob

    clean_token = str(access_token or "").strip()
    if clean_token and not any(k.lower() == "authorization" for k in extra_headers):
        extra_headers["Authorization"] = f"Bearer {clean_token}"

    return cookie_hdr, extra_headers


def _operator_global_headers(http: AgenticHTTPClient) -> dict[str, str]:
    """Return validated operator headers that must accompany every browser request."""
    actors = getattr(http, "actors", None)
    getter = getattr(actors, "global_headers", None)
    if not callable(getter):
        return {}
    try:
        raw = getter()
    except (TypeError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items() if k and v is not None}


def _operator_browser_headers(http: AgenticHTTPClient) -> dict[str, str]:
    """Return non-auth operator global headers safe for Playwright route continuation."""
    global_headers = _operator_global_headers(http)
    if not global_headers:
        return {}
    _, safe_headers = _normalize_browser_auth_parts(base_headers=global_headers)
    return safe_headers


def _operator_user_agent(http: AgenticHTTPClient, default_ua: str = _BROWSER_USER_AGENT) -> str:
    """Return custom operator User-Agent when configured, otherwise ``default_ua``."""
    for key, value in _operator_global_headers(http).items():
        if key.strip().lower() == "user-agent" and value.strip():
            return value.strip()
    return default_ua


def _merge_browser_route_headers(
    req_headers: dict[str, Any],
    extra_headers: dict[str, str],
    *,
    override_names: frozenset[str] = frozenset(),
) -> dict[str, str]:
    """Merge Playwright request headers with ``extra_headers`` (case-insensitive)."""
    merged = {
        str(k): str(v)
        for k, v in (req_headers or {}).items()
        if k and not str(k).startswith(":")
    }
    existing_lower = {k.lower() for k in merged}
    for hk, hv in extra_headers.items():
        low = hk.lower()
        if low in override_names:
            for existing_key in [ek for ek in merged if ek.lower() == low]:
                merged.pop(existing_key, None)
            merged[hk] = hv
            existing_lower.add(low)
        elif low not in existing_lower:
            merged[hk] = hv
            existing_lower.add(low)
    return merged


def _extract_actor_browser_auth(http: AgenticHTTPClient, actor: str) -> tuple[str, dict[str, str]]:
    """Extract host-side Playwright ``(cookie_header, extra_headers)`` for ``actor``.

    Uses ``http.actors.get_browser_auth_state(actor)`` when available, otherwise reads
    ``ActorSession`` cookies/access_token/base_headers under lock. Anonymous sessions
    still receive operator global headers, but never credentials. Values returned here
    are strictly for host-side Playwright use and must NEVER be included in any tool
    output dictionary.
    """
    clean_actor = str(actor or "anon").strip() or "anon"
    global_headers = _operator_global_headers(http)

    def _with_global(parts: tuple[str, dict[str, str]]) -> tuple[str, dict[str, str]]:
        cookie_hdr, extra_headers = parts
        for key, value in global_headers.items():
            if not any(existing.lower() == key.lower() for existing in extra_headers):
                extra_headers[key] = value
        return cookie_hdr, extra_headers

    if clean_actor == "anon":
        return _normalize_browser_auth_parts(base_headers=global_headers)

    get_state = getattr(http.actors, "get_browser_auth_state", None)
    if callable(get_state):
        state = get_state(clean_actor)
        if isinstance(state, tuple) and len(state) == 2:
            raw_cookie, raw_headers = state
            if isinstance(raw_cookie, dict):
                return _with_global(_normalize_browser_auth_parts(
                    cookies_map=raw_cookie,
                    base_headers=raw_headers if isinstance(raw_headers, dict) else {},
                ))
            return _with_global(_normalize_browser_auth_parts(
                cookie_blob=str(raw_cookie or ""),
                base_headers=raw_headers if isinstance(raw_headers, dict) else {},
            ))
        if isinstance(state, dict):
            raw_hdrs = state.get("extra_headers") or state.get("headers") or state.get("base_headers")
            return _with_global(_normalize_browser_auth_parts(
                cookie_blob=str(state.get("cookie") or ""),
                cookies_map=state.get("cookies") if isinstance(state.get("cookies"), dict) else None,
                base_headers=raw_hdrs if isinstance(raw_hdrs, dict) else None,
                access_token=str(state.get("access_token") or state.get("bearer_token") or ""),
            ))
        return _with_global(("", {}))

    session = http.actors.get(clean_actor)
    lock = getattr(session, "_lock", None)
    ctx = lock if lock is not None else nullcontext()
    with ctx:
        base_headers = dict(getattr(session, "base_headers", None) or {})
        cookies_map = dict(getattr(session, "cookies", None) or {})
        access_token = str(getattr(session, "access_token", "") or "").strip()

    return _with_global(_normalize_browser_auth_parts(
        cookies_map=cookies_map,
        base_headers=base_headers,
        access_token=access_token,
    ))


def _extract_actor_cookie_records(
    http: AgenticHTTPClient,
    actor: str,
    *,
    base_url: str,
    fallback_cookie_hdr: str = "",
) -> list[dict[str, Any]]:
    """Build scope-validated Playwright cookie dicts preserving per-origin/domain attributes when available."""
    clean_actor = str(actor or "anon").strip() or "anon"
    if clean_actor == "anon":
        return []

    raw_records: Any = None
    get_state = getattr(http.actors, "get_browser_auth_state", None)
    if callable(get_state):
        state = get_state(clean_actor)
        if isinstance(state, dict) and isinstance(state.get("cookie_records"), (list, tuple)):
            raw_records = state.get("cookie_records")

    if raw_records is None:
        try:
            session = http.actors.get(clean_actor)
        except (ValueError, KeyError):
            session = None
        if session is not None:
            lock = getattr(session, "_lock", None)
            ctx = lock if lock is not None else nullcontext()
            with ctx:
                raw_records = list(getattr(session, "cookie_records", None) or ())

    scope_guard = getattr(http, "scope_guard", None)
    parsed_base = urlsplit(str(base_url or "").strip())
    base_scheme = (parsed_base.scheme or "http").lower()
    base_host = (parsed_base.hostname or "").strip().lower().rstrip(".")
    base_port = parsed_base.port or (443 if base_scheme == "https" else 80)

    def _domain_allowed(raw_domain: str) -> bool:
        dom = raw_domain.strip().lower().lstrip(".").rstrip(".")
        if not dom:
            return False
        if dom == base_host or (base_host and base_host.endswith("." + dom)):
            if scope_guard is not None and any(
                rule.matches_origin(base_scheme, dom, base_port)
                for rule in getattr(scope_guard, "_out_of_scope_origin_rules", ())
            ):
                return False
            return True
        if scope_guard is None:
            return False
        for sch, prt in ((base_scheme, base_port), ("https", 443), ("http", 80)):
            if scope_guard.check_origin(sch, dom, prt):
                return True
        return False

    cookies_out: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str, str]] = set()
    recorded_names: set[str] = set()
    rejected_record_names: set[str] = set()

    for rec in raw_records or ():
        if not isinstance(rec, dict):
            continue
        cname = str(rec.get("name") or "").strip()
        cval = rec.get("value")
        if not cname or not isinstance(cval, str):
            continue
        raw_domain = str(rec.get("domain") or "").strip()
        raw_url = str(rec.get("url") or rec.get("origin") or "").strip()
        cpath = str(rec.get("path") or "/").strip() or "/"
        cookie_dict: dict[str, Any]
        if raw_domain:
            if not _domain_allowed(raw_domain):
                rejected_record_names.add(cname)
                continue
            cookie_dict = {
                "name": cname,
                "value": cval,
                "domain": raw_domain,
                "path": cpath,
            }
            dedup_scope = f"d:{raw_domain.lower()}:{cpath}"
        elif raw_url:
            try:
                checked_url = _resolve_and_check_scope(http, raw_url)
            except ScopeViolationError:
                rejected_record_names.add(cname)
                continue
            cookie_dict = {
                "name": cname,
                "value": cval,
                "url": checked_url,
            }
            dedup_scope = f"u:{_normalize_js_origin(checked_url)}"
        else:
            cookie_dict = {
                "name": cname,
                "value": cval,
                "url": base_url,
            }
            dedup_scope = f"u:{_normalize_js_origin(base_url)}"

        if isinstance(rec.get("secure"), bool):
            cookie_dict["secure"] = rec["secure"]
        if isinstance(rec.get("httpOnly"), bool):
            cookie_dict["httpOnly"] = rec["httpOnly"]
        raw_same_site = str(rec.get("sameSite") or "").strip().lower()
        norm_same_site = {"strict": "Strict", "lax": "Lax", "none": "None"}.get(raw_same_site, "")
        if norm_same_site:
            cookie_dict["sameSite"] = norm_same_site

        dedup_key = (cname, dedup_scope, str(cookie_dict.get("domain") or ""), str(cookie_dict.get("url") or ""))
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        recorded_names.add(cname)
        cookies_out.append(cookie_dict)

    for cname, cval in _parse_cookie_pairs(fallback_cookie_hdr):
        if cname in recorded_names or cname in rejected_record_names:
            continue
        cookies_out.append({"name": cname, "value": cval, "url": base_url})

    return cookies_out


def _extract_actor_local_storage(http: AgenticHTTPClient, actor: str) -> dict[str, str]:
    """Extract host-side same-origin ``localStorage`` key/value pairs for ``actor``.

    Returns ``{}`` for ``"anon"``. Checks ``http.actors.get_browser_auth_state(actor)``
    first when it returns a dict containing ``"local_storage"``, otherwise falls back
    to reading ``session.local_storage`` under ``session._lock``. Values returned here
    are strictly for host-side Playwright use and must NEVER leak to model outputs.
    """
    clean_actor = str(actor or "anon").strip() or "anon"
    if clean_actor == "anon":
        return {}

    def _clean_map(raw: Any) -> dict[str, str]:
        if not isinstance(raw, dict):
            return {}
        out: dict[str, str] = {}
        for k, v in raw.items():
            if isinstance(k, str) and isinstance(v, str) and k.strip():
                out[k.strip()] = v
        return out

    get_state = getattr(http.actors, "get_browser_auth_state", None)
    used_get_state = callable(get_state)
    if used_get_state:
        assert callable(get_state)
        state = get_state(clean_actor)
        if isinstance(state, dict) and isinstance(state.get("local_storage"), dict):
            return _clean_map(state.get("local_storage"))

    try:
        session = http.actors.get(clean_actor)
    except (ValueError, KeyError):
        if used_get_state:
            return {}
        raise

    lock = getattr(session, "_lock", None)
    ctx = lock if lock is not None else nullcontext()
    with ctx:
        raw_ls = getattr(session, "local_storage", None)
        return _clean_map(raw_ls)


def _extract_actor_local_storage_by_origin(
    http: AgenticHTTPClient,
    actor: str,
) -> dict[str, dict[str, str]]:
    """Extract scope-validated per-origin ``localStorage`` maps for ``actor`` when present."""
    clean_actor = str(actor or "anon").strip() or "anon"
    if clean_actor == "anon":
        return {}

    raw_by_origin: Any = None
    get_state = getattr(http.actors, "get_browser_auth_state", None)
    used_get_state = callable(get_state)
    if used_get_state:
        assert callable(get_state)
        state = get_state(clean_actor)
        if isinstance(state, dict) and isinstance(state.get("local_storage_by_origin"), dict):
            raw_by_origin = state.get("local_storage_by_origin")

    if raw_by_origin is None:
        try:
            session = http.actors.get(clean_actor)
        except (ValueError, KeyError):
            if used_get_state:
                return {}
            raise
        lock = getattr(session, "_lock", None)
        ctx = lock if lock is not None else nullcontext()
        with ctx:
            raw_by_origin = getattr(session, "local_storage_by_origin", None)

    if not isinstance(raw_by_origin, dict):
        return {}

    out: dict[str, dict[str, str]] = {}
    for raw_orig, raw_kv in raw_by_origin.items():
        if not isinstance(raw_orig, str) or not isinstance(raw_kv, dict):
            continue
        norm_orig = _normalize_js_origin(raw_orig)
        if not norm_orig:
            continue
        try:
            _resolve_and_check_scope(http, norm_orig)
        except ScopeViolationError:
            continue
        cleaned_kv: dict[str, str] = {}
        for k, v in raw_kv.items():
            if isinstance(k, str) and isinstance(v, str) and k.strip():
                cleaned_kv[k.strip()] = v
        if cleaned_kv:
            merged = out.setdefault(norm_orig, {})
            merged.update(cleaned_kv)
    return out


def _normalize_js_origin(expected_origin: str) -> str:
    """Normalize an http(s) URL or origin into browser ``window.location.origin`` form."""
    raw = str(expected_origin or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        return ""
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return ""
    host_fmt = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if port is None or port == default_port:
        return f"{scheme}://{host_fmt}"
    return f"{scheme}://{host_fmt}:{port}"


def _build_origin_localstorage_init_script(expected_origin: str, local_storage: dict[str, str]) -> str:
    """Build a strictly same-origin-guarded Playwright init script seeding ``localStorage``."""
    norm_origin = _normalize_js_origin(expected_origin)
    entries = [
        [k.strip(), v]
        for k, v in (local_storage or {}).items()
        if isinstance(k, str) and isinstance(v, str) and k.strip()
    ]
    if not norm_origin or not entries:
        return ""
    origin_json = json.dumps(norm_origin, ensure_ascii=True)
    entries_json = json.dumps(entries, ensure_ascii=True)
    return (
        "(() => {\n"
        f"  if (window.location.origin === {origin_json}) {{\n"
        "    try {\n"
        f"      for (const [k, v] of {entries_json}) {{\n"
        "        window.localStorage.setItem(k, v);\n"
        "      }\n"
        "    } catch (_) {}\n"
        "  }\n"
        "})();\n"
    )


def _build_multi_origin_localstorage_init_script(
    local_storage_by_origin: dict[str, dict[str, str]] | None = None,
    *,
    fallback_origin: str = "",
    fallback_local_storage: dict[str, str] | None = None,
) -> str:
    """Build an origin-isolated Playwright init script from ``local_storage_by_origin`` or flat fallback."""
    if not local_storage_by_origin:
        return _build_origin_localstorage_init_script(
            fallback_origin,
            fallback_local_storage or {},
        )

    origin_entries: dict[str, list[list[str]]] = {}
    norm_fb = _normalize_js_origin(fallback_origin)
    merged_by_origin: dict[str, dict[str, str]] = {}
    if norm_fb and fallback_local_storage:
        fb_clean = {
            k.strip(): v
            for k, v in fallback_local_storage.items()
            if isinstance(k, str) and isinstance(v, str) and k.strip()
        }
        if fb_clean:
            merged_by_origin[norm_fb] = fb_clean

    for raw_orig, kv in local_storage_by_origin.items():
        norm_orig = _normalize_js_origin(raw_orig)
        if not norm_orig or not isinstance(kv, dict):
            continue
        target = merged_by_origin.setdefault(norm_orig, {})
        for k, v in kv.items():
            if isinstance(k, str) and isinstance(v, str) and k.strip():
                target[k.strip()] = v

    for orig_key, kv in merged_by_origin.items():
        pairs = [[k, v] for k, v in kv.items()]
        if pairs:
            origin_entries[orig_key] = pairs

    if not origin_entries:
        return ""

    map_json = json.dumps(origin_entries, ensure_ascii=True)
    return (
        "(() => {\n"
        f"  const map = {map_json};\n"
        "  if (Object.prototype.hasOwnProperty.call(map, window.location.origin) && map[window.location.origin]) {\n"
        "    try {\n"
        "      for (const [k, v] of map[window.location.origin]) {\n"
        "        window.localStorage.setItem(k, v);\n"
        "      }\n"
        "    } catch (_) {}\n"
        "  }\n"
        "})();\n"
    )


def _collect_actor_secrets(
    http: AgenticHTTPClient,
    cookie_hdr: str,
    extra_headers: dict[str, str],
    local_storage: dict[str, str] | None = None,
    *,
    cookie_records: Sequence[dict[str, Any]] = (),
    local_storage_by_origin: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Collect sensitive strings for defense-in-depth scrubbing of model-facing outputs."""
    secrets: list[str] = []
    all_secrets_fn = getattr(http.actors, "all_secrets", None)
    if callable(all_secrets_fn):
        for val in all_secrets_fn() or ():
            sval = str(val or "")
            if len(sval) >= 4:
                secrets.append(sval)
    if len(cookie_hdr) >= 4:
        secrets.append(cookie_hdr)
    for _, cv in _parse_cookie_pairs(cookie_hdr):
        if len(cv) >= 4:
            secrets.append(cv)
    for crec in cookie_records:
        if isinstance(crec, dict):
            cval = str(crec.get("value") or "")
            if len(cval) >= 4:
                secrets.append(cval)
    for hk, hv in extra_headers.items():
        if hk.lower() in {"authorization", "cookie", "x-api-key", "x-csrf-token"} and len(hv) >= 4:
            secrets.append(hv)
            parts = hv.strip().split(None, 1)
            if len(parts) == 2 and len(parts[1].strip()) >= 4:
                secrets.append(parts[1].strip())

    def _add_ls_values(kv: dict[str, str] | None) -> None:
        for lv in (kv or {}).values():
            sval = str(lv or "")
            if len(sval) >= 4:
                secrets.append(sval)
                parts = sval.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() == "bearer" and len(parts[1].strip()) >= 4:
                    secrets.append(parts[1].strip())

    _add_ls_values(local_storage)
    for kv in (local_storage_by_origin or {}).values():
        _add_ls_values(kv)
    return sorted(set(secrets), key=len, reverse=True)


def _redact_secrets(text: str, secrets: Sequence[str]) -> str:
    """Scrub any known actor secret values from a model-facing string."""
    out = str(text or "")
    for secret in secrets:
        if secret and secret in out:
            out = out.replace(secret, "<REDACTED>")
    return out


def _resolve_and_check_scope(http: AgenticHTTPClient, raw_url: str) -> str:
    """Resolve ``raw_url`` against ``http.base_url`` and enforce strict scope rules."""
    raw = str(raw_url or "").strip()
    if not raw:
        raise ScopeViolationError("URL is required")
    if raw.startswith("//"):
        raise ScopeViolationError(f"scheme-relative cross-origin URL blocked: {raw}")

    resolve_fn = getattr(http, "resolve_in_scope", None)
    if callable(resolve_fn):
        clean_url, _path, _query = resolve_fn(raw)
    else:
        base_parsed = urlsplit(http.base_url)
        resolved = urljoin(http.base_url, raw)
        parsed = urlsplit(resolved)
        if (parsed.scheme, parsed.netloc) != (base_parsed.scheme, base_parsed.netloc):
            raise ScopeViolationError(
                f"out-of-scope URL {resolved!r}; allowed origin is {http.base_url}"
            )
        clean_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))

    frag = urlsplit(raw).fragment
    full_url = f"{clean_url}#{frag}" if frag.startswith("/") else clean_url

    check_scope = getattr(http, "_check_scope", None)
    if callable(check_scope):
        decision = check_scope(full_url)
        if decision is False:
            raise ScopeViolationError(f"URL excluded by scope policy: {full_url!r}")

    return full_url


def _budget_remaining(http: AgenticHTTPClient) -> int:
    """Return remaining WireBudget allowance on ``http``."""
    budget = http.budget
    lock = getattr(budget, "_lock", None)
    ctx = lock if lock is not None else nullcontext()
    with ctx:
        if getattr(budget, "blocked_reason", ""):
            return 0
        return max(0, int(budget.limit) - int(budget.used))


def _consume_budget(http: AgenticHTTPClient, count: int) -> int:
    """Consume up to ``count`` requests from ``http.budget``."""
    consumed = 0
    for _ in range(max(0, int(count))):
        allowed, _reason = http.budget.consume()
        if not allowed:
            break
        consumed += 1
    return consumed


def _compact_same_origin_url(
    raw_url: str,
    *,
    base_url: str,
    base_scheme: str,
    base_netloc: str,
    allow_fragment_route: bool = False,
    scope_guard: Any | None = None,
) -> str | None:
    """Validate primary or in-scope sibling URL; compact primary to ``/path?query`` and preserve origin on siblings."""
    raw = str(raw_url or "").strip()
    if not raw:
        return None
    low = raw.lower()
    if low.startswith(_NON_HTTP_SCHEMES):
        return None
    resolved = urljoin(base_url, raw)
    parsed = urlsplit(resolved)
    scheme_low = parsed.scheme.lower()
    netloc_low = parsed.netloc.lower()
    if scheme_low not in {"http", "https"} or not netloc_low:
        return None
    path = parsed.path or "/"
    is_primary = scheme_low == base_scheme.lower() and netloc_low == base_netloc.lower()
    if not is_primary:
        if scope_guard is None:
            return None
        try:
            scope_guard.check_url(resolved)
        except ValueError:
            return None
        compact = f"{scheme_low}://{netloc_low}{path}"
        if parsed.query:
            compact = f"{compact}?{parsed.query}"
    else:
        if scope_guard is not None:
            try:
                scope_guard.check_url(resolved)
            except ValueError:
                return None
        compact = f"{path}?{parsed.query}" if parsed.query else path
    if allow_fragment_route and parsed.fragment.startswith("/"):
        compact = f"{compact}#{parsed.fragment}"
    return compact


def _fn_prefers_headers_kwarg(fn: Callable[..., Any]) -> bool:
    """Return True if ``fn`` explicitly accepts ``headers`` rather than ``extra_headers``."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return "headers" in params and "extra_headers" not in params


def _fn_accepts_kwarg(fn: Callable[..., Any], kwarg_name: str) -> bool:
    """Return True if ``fn`` accepts ``kwarg_name`` explicitly or via ``**kwargs``."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return kwarg_name in params or any(
        p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values()
    )


def _extract_safe_field_names(raw_fields: Any) -> list[str]:
    """Extract deduplicated form/body parameter names ONLY (never values or passwords)."""
    if not isinstance(raw_fields, (list, tuple)):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in raw_fields:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
        else:
            name = str(item or "").strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name[:64])
        if len(names) >= 24:
            break
    return names


def _build_crawl_wire_gate(http: AgenticHTTPClient) -> Callable[[str, str, dict[str, Any]], tuple[bool, str]]:
    """Build a read-only same-origin wire gate for ``kryon_core.surface.crawl.crawl_site``."""

    def _gate(method: str, req_url: str, _req_headers: dict[str, Any]) -> tuple[bool, str]:
        norm_method = str(method or "").strip().upper()
        if norm_method not in {"GET", "HEAD", "OPTIONS"}:
            return False, "read_only_crawl_method_blocked"
        try:
            _resolve_and_check_scope(http, req_url)
        except ScopeViolationError:
            return False, "scope_violation"
        return True, "allowed"

    # Budget accounting for agentic crawls is owned by run_browser_crawl on http.budget.
    setattr(_gate, "accounts_campaign_requests", True)
    return _gate


def run_browser_crawl(
    http: AgenticHTTPClient,
    surface_tracker: SurfaceFrontierTracker | None,
    *,
    url: str = "/",
    actor: str = "anon",
    max_pages: int = 6,
    wait_ms: int = 400,
    timeout_ms: int = 12000,
    crawl_fn: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run a bounded, read-only, scope-locked Playwright crawl and ingest into ``surface_tracker``."""
    full_url = _resolve_and_check_scope(http, url)
    scope_guard = getattr(http, "scope_guard", None)
    base_parsed = urlsplit(http.base_url)
    base_scheme = base_parsed.scheme
    base_netloc = base_parsed.netloc
    compact_start = (
        _compact_same_origin_url(
            full_url,
            base_url=http.base_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        or "/"
    )

    clean_actor = str(actor or "anon").strip() or "anon"
    cookie_hdr, extra_headers = _extract_actor_browser_auth(http, clean_actor)
    local_storage = _extract_actor_local_storage(http, clean_actor)
    local_storage_by_origin = _extract_actor_local_storage_by_origin(http, clean_actor)
    cookie_records = _extract_actor_cookie_records(
        http,
        clean_actor,
        base_url=http.base_url,
        fallback_cookie_hdr=cookie_hdr,
    )
    secrets = _collect_actor_secrets(
        http,
        cookie_hdr,
        extra_headers,
        local_storage=local_storage,
        cookie_records=cookie_records,
        local_storage_by_origin=local_storage_by_origin,
    )

    remaining = _budget_remaining(http)
    if remaining <= 0:
        raise BudgetExhaustedError("campaign request budget exhausted")

    clamped_pages = max(1, min(int(max_pages), _MAX_PAGES_UPPER))
    eff_max_pages = min(clamped_pages, remaining)
    eff_wait_ms = max(0, min(int(wait_ms), _MAX_WAIT_MS))
    eff_timeout_ms = max(_MIN_TIMEOUT_MS, min(int(timeout_ms), _MAX_TIMEOUT_MS))
    allow_subdomains = bool(getattr(scope_guard, "is_multi_origin", False))

    if crawl_fn is None and (not HAS_PLAYWRIGHT or _default_crawl_site is None):
        return {
            "ok": False,
            "error": "playwright_unavailable",
            "pages_crawled": 0,
            "pages": [],
            "links": [],
            "forms": [],
            "xhr_calls": [],
        }

    if crawl_fn is not None:
        call_kwargs: dict[str, Any] = {
            "allow_subdomains": allow_subdomains,
            "max_pages": eff_max_pages,
            "wait_ms": eff_wait_ms,
            "timeout_ms": eff_timeout_ms,
            "cookie": cookie_hdr,
        }
        if _fn_prefers_headers_kwarg(crawl_fn):
            call_kwargs["headers"] = extra_headers
        else:
            call_kwargs["extra_headers"] = extra_headers
        if local_storage and _fn_accepts_kwarg(crawl_fn, "local_storage"):
            call_kwargs["local_storage"] = dict(local_storage)
        if local_storage_by_origin and _fn_accepts_kwarg(crawl_fn, "local_storage_by_origin"):
            call_kwargs["local_storage_by_origin"] = {
                k: dict(v) for k, v in local_storage_by_origin.items()
            }
        if cookie_records and _fn_accepts_kwarg(crawl_fn, "cookie_records"):
            call_kwargs["cookie_records"] = [dict(c) for c in cookie_records]
        raw = crawl_fn(full_url, **call_kwargs)
    else:
        assert _default_crawl_site is not None
        crawl_headers = dict(extra_headers)
        custom_ua = _operator_user_agent(http, default_ua="")
        if custom_ua and not any(k.lower() == "user-agent" for k in crawl_headers):
            crawl_headers["User-Agent"] = custom_ua
        default_kwargs: dict[str, Any] = {
            "max_pages": eff_max_pages,
            "cookie": cookie_hdr,
            "headers": crawl_headers,
            "timeout_ms": eff_timeout_ms,
            "allow_subdomains": allow_subdomains,
            "wait_ms": eff_wait_ms,
            "wire_gate": _build_crawl_wire_gate(http),
        }
        accepts_ls = _fn_accepts_kwarg(_default_crawl_site, "local_storage")
        if local_storage and accepts_ls:
            default_kwargs["local_storage"] = dict(local_storage)
        ls_init_script = (
            ""
            if (accepts_ls and not local_storage_by_origin)
            else _build_multi_origin_localstorage_init_script(
                local_storage_by_origin,
                fallback_origin=http.base_url,
                fallback_local_storage=local_storage,
            )
        )
        start_origin = _normalize_js_origin(full_url)
        extra_crawl_cookies = [
            c
            for c in cookie_records
            if "domain" in c or _normalize_js_origin(str(c.get("url") or "")) != start_origin
        ]
        with _inject_crawl_browser_state(ls_init_script, extra_crawl_cookies):
            raw = _default_crawl_site(full_url, **default_kwargs)

    raw_dict = raw if isinstance(raw, dict) else {}
    raw_pages_val = raw_dict.get("pages")
    raw_pages: list[Any] = raw_pages_val if isinstance(raw_pages_val, list) else []

    if not raw_dict.get("ok"):
        if raw_pages:
            _consume_budget(http, min(remaining, len(raw_pages)))
        err_text = _redact_secrets(str(raw_dict.get("error") or "browser_crawl_failed"), secrets)[:300]
        return {
            "ok": False,
            "error": err_text,
            "start_url": compact_start,
            "actor": clean_actor,
            "pages_crawled": 0,
            "pages": [],
            "links": [],
            "forms": [],
            "xhr_calls": [],
            "truncated": False,
        }

    pages_to_charge = min(remaining, max(1, len(raw_pages)))
    _consume_budget(http, pages_to_charge)

    # 1. Filter & compact pages strictly to in-scope origins
    all_pages: list[dict[str, Any]] = []
    seen_pages: set[str] = set()
    for p_item in raw_pages:
        if isinstance(p_item, dict):
            raw_p_url = str(p_item.get("url") or "")
            p_status = int(p_item.get("status") or 0)
            p_title = _redact_secrets(str(p_item.get("title") or "").strip(), secrets)[:120]
            p_ctype = str(p_item.get("content_type") or "").strip().lower()[:64]
        else:
            raw_p_url = str(p_item or "")
            p_status = 0
            p_title = ""
            p_ctype = ""
        compact_p = _compact_same_origin_url(
            raw_p_url,
            base_url=full_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        if compact_p is None or compact_p in seen_pages:
            continue
        seen_pages.add(compact_p)
        page_entry: dict[str, Any] = {
            "url": _redact_secrets(compact_p, secrets),
            "status": p_status,
            "title": p_title,
        }
        if p_ctype:
            page_entry["content_type"] = p_ctype
        all_pages.append(page_entry)

    # 2. Filter, drop static assets, deduplicate & compact links + hash routes
    all_links: list[str] = []
    seen_links: set[str] = set()
    raw_link_sources: list[Any] = []
    if isinstance(raw_dict.get("links"), list):
        raw_link_sources.extend(raw_dict["links"])
    if isinstance(raw_dict.get("hash_routes"), list):
        raw_link_sources.extend(raw_dict["hash_routes"])
    for l_item in raw_link_sources:
        raw_l = str(l_item.get("url") or "") if isinstance(l_item, dict) else str(l_item or "")
        compact_l = _compact_same_origin_url(
            raw_l,
            base_url=full_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        if compact_l is None or is_static_asset_url(compact_l):
            continue
        safe_l = _redact_secrets(compact_l, secrets)
        if safe_l not in seen_links:
            seen_links.add(safe_l)
            all_links.append(safe_l)

    # 3. Filter, deduplicate & compact forms (field names only, NEVER values)
    all_forms: list[dict[str, Any]] = []
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
    raw_forms_val = raw_dict.get("forms")
    raw_forms: list[Any] = raw_forms_val if isinstance(raw_forms_val, list) else []
    for f_item in raw_forms:
        if not isinstance(f_item, dict):
            continue
        page_ref = str(f_item.get("page") or full_url)
        raw_action = str(f_item.get("action") or f_item.get("url") or page_ref)
        compact_action = _compact_same_origin_url(
            raw_action,
            base_url=urljoin(full_url, page_ref),
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            scope_guard=scope_guard,
        )
        if compact_action is None:
            continue
        method = str(f_item.get("method") or "GET").strip().upper() or "GET"
        fields = _extract_safe_field_names(f_item.get("fields") or f_item.get("params") or [])
        safe_action = _redact_secrets(compact_action, secrets)
        form_key = (method, safe_action, tuple(fields))
        if form_key in seen_forms:
            continue
        seen_forms.add(form_key)
        all_forms.append({
            "action": safe_action,
            "method": method,
            "fields": fields,
        })

    # 4. Filter, deduplicate & compact XHR / fetch calls
    all_xhr: list[dict[str, Any]] = []
    xhr_index: dict[tuple[str, str], dict[str, Any]] = {}
    raw_xhr_sources: list[Any] = []
    for key_name in ("xhr", "xhr_calls", "api_requests"):
        val = raw_dict.get(key_name)
        if isinstance(val, list):
            raw_xhr_sources.extend(val)
    for x_item in raw_xhr_sources:
        if not isinstance(x_item, dict):
            continue
        raw_x_url = str(x_item.get("url") or "")
        compact_x = _compact_same_origin_url(
            raw_x_url,
            base_url=full_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            scope_guard=scope_guard,
        )
        if compact_x is None:
            continue
        x_method = str(x_item.get("method") or "GET").strip().upper() or "GET"
        x_status = int(x_item.get("status") or 0)
        body_fields = _extract_safe_field_names(x_item.get("body_fields") or [])
        safe_x_url = _redact_secrets(compact_x, secrets)
        x_key = (x_method, safe_x_url)
        existing = xhr_index.get(x_key)
        if existing is not None:
            if x_status and not existing.get("status"):
                existing["status"] = x_status
            if body_fields:
                merged_bf = list(dict.fromkeys([*(existing.get("body_fields") or []), *body_fields]))[:24]
                existing["body_fields"] = merged_bf
            continue
        entry: dict[str, Any] = {
            "method": x_method,
            "url": safe_x_url,
            "status": x_status,
        }
        if body_fields:
            entry["body_fields"] = body_fields
        xhr_index[x_key] = entry
        all_xhr.append(entry)

    # 5. Ingest discovered in-scope surface into SurfaceFrontierTracker
    if surface_tracker is not None:
        surface_payload: dict[str, Any] = {
            "url": full_url,
            "links": [{"url": link_u, "method": "GET"} for link_u in all_links],
            "spa_routes": [{"url": p["url"], "method": "GET"} for p in all_pages],
            "forms": [
                {
                    "url": f["action"],
                    "method": f["method"],
                    "params": list(f["fields"]),
                }
                for f in all_forms
            ],
            "js_calls": [
                {
                    "url": x["url"],
                    "method": x["method"],
                    "params": list(x.get("body_fields") or []),
                }
                for x in all_xhr
            ],
        }
        surface_tracker.ingest_surface(surface_payload, actor=clean_actor)

    truncated = bool(
        len(all_pages) > _MAX_RETURNED_PAGES
        or len(all_links) > _MAX_RETURNED_LINKS
        or len(all_forms) > _MAX_RETURNED_FORMS
        or len(all_xhr) > _MAX_RETURNED_XHR
        or (eff_max_pages < clamped_pages and len(raw_pages) >= eff_max_pages)
    )

    return {
        "ok": True,
        "start_url": compact_start,
        "actor": clean_actor,
        "pages_crawled": len(all_pages),
        "pages": all_pages[:_MAX_RETURNED_PAGES],
        "links": all_links[:_MAX_RETURNED_LINKS],
        "forms": all_forms[:_MAX_RETURNED_FORMS],
        "xhr_calls": all_xhr[:_MAX_RETURNED_XHR],
        "truncated": truncated,
    }


def _redact_query_to_same_origin(
    raw_url: str,
    *,
    base_url: str,
    base_scheme: str,
    base_netloc: str,
    scope_guard: Any | None = None,
) -> tuple[str, str, list[str]] | None:
    """Resolve ``raw_url`` within authorized origins and redact all query parameter values."""
    compact = _compact_same_origin_url(
        raw_url,
        base_url=base_url,
        base_scheme=base_scheme,
        base_netloc=base_netloc,
        scope_guard=scope_guard,
    )
    if compact is None:
        return None
    parsed = urlsplit(compact)
    path = parsed.path or "/"
    q_names = sorted({k.strip() for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if k.strip()})
    origin_path = (
        f"{parsed.scheme}://{parsed.netloc}{path}"
        if compact.lower().startswith(("http://", "https://")) and parsed.netloc
        else path
    )
    safe_url = f"{origin_path}?{'&'.join(f'{k}=<value>' for k in q_names)}" if q_names else origin_path
    return safe_url, origin_path, q_names


def _sanitize_runtime_requests(
    raw_events: Any,
    *,
    base_url: str,
    base_scheme: str,
    base_netloc: str,
    scope_guard: Any | None = None,
) -> list[dict[str, Any]]:
    """Normalize runtime fetch/XHR hook metadata into compact in-scope dicts without values."""
    if callable(_normalize_runtime_events) and isinstance(raw_events, list):
        normalized = _normalize_runtime_events(raw_events)
        source_items = normalized.get("requests") if isinstance(normalized, dict) else []
    elif isinstance(raw_events, list):
        source_items = raw_events
    else:
        source_items = []

    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for item in source_items if isinstance(source_items, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "fetch").strip().lower()
        if kind == "websocket":
            continue
        raw_u = str(item.get("url") or item.get("path") or "")
        redacted = _redact_query_to_same_origin(
            raw_u,
            base_url=base_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            scope_guard=scope_guard,
        )
        if redacted is None:
            continue
        safe_url, path, q_names = redacted
        method = str(item.get("method") or "GET").strip().upper() or "GET"
        header_names = _extract_safe_field_names(item.get("header_names") or [])
        body_fields = _extract_safe_field_names(item.get("body_fields") or [])
        raw_status = item.get("status")
        status = int(raw_status) if isinstance(raw_status, (int, float)) else 0
        dedup_key = (kind, method, safe_url, status, tuple(header_names), tuple(body_fields))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        rec: dict[str, Any] = {
            "kind": kind,
            "method": method,
            "url": safe_url,
            "path": path,
            "query_params": q_names,
            "header_names": header_names,
            "body_fields": body_fields,
            "status": status,
        }
        cleaned.append(rec)
        if len(cleaned) >= _MAX_RETURNED_RUNTIME_REQUESTS:
            break
    return cleaned


def _inspect_rendered_page_playwright(
    http: AgenticHTTPClient,
    *,
    full_url: str,
    cookie_hdr: str,
    extra_headers: dict[str, str],
    local_storage: dict[str, str] | None = None,
    local_storage_by_origin: dict[str, dict[str, str]] | None = None,
    cookie_records: Sequence[dict[str, Any]] = (),
    marker: str,
    wait_ms: int,
    timeout_ms: int,
) -> dict[str, Any]:
    """Execute read-only isolated Chromium page inspection synchronously."""
    assert _sync_playwright is not None

    def _run() -> dict[str, Any]:
        console_error_count = 0
        blocked_requests: list[dict[str, str]] = []

        def _inc_console_error() -> None:
            nonlocal console_error_count
            console_error_count += 1

        operator_override_names = frozenset(k.lower() for k in _operator_browser_headers(http))
        with _sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
            context = browser.new_context(
                ignore_https_errors=True,
                service_workers="block",
                user_agent=_operator_user_agent(http),
            )
            try:
                ls_init_script = _build_multi_origin_localstorage_init_script(
                    local_storage_by_origin,
                    fallback_origin=http.base_url,
                    fallback_local_storage=local_storage,
                )
                if ls_init_script:
                    context.add_init_script(ls_init_script)

                if callable(_build_runtime_hook_script):
                    context.add_init_script(_build_runtime_hook_script())

                if cookie_records:
                    context.add_cookies([dict(c) for c in cookie_records])
                else:
                    cookie_pairs = _parse_cookie_pairs(cookie_hdr)
                    if cookie_pairs:
                        context.add_cookies([
                            {"name": cname, "value": cval, "url": http.base_url}
                            for cname, cval in cookie_pairs
                        ])

                async def _on_websocket(socket: Any) -> None:
                    route_obj = getattr(socket, "_impl_obj", socket)
                    closing = route_obj.close(code=1008, reason="readonly inspector: websocket blocked")
                    if inspect.isawaitable(closing):
                        await closing

                def _on_route(route: Any) -> None:
                    req = route.request
                    req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
                    req_url = str(getattr(req, "url", "") or "")
                    if req_method not in {"GET", "HEAD"}:
                        blocked_requests.append({"method": req_method, "reason": "non_readonly_method"})
                        route.abort("blockedbyclient")
                        return
                    try:
                        _resolve_and_check_scope(http, req_url)
                    except ScopeViolationError:
                        blocked_requests.append({"method": req_method, "reason": "off_origin"})
                        route.abort("blockedbyclient")
                        return
                    if extra_headers:
                        try:
                            raw_req_headers = dict(req.all_headers() or {})
                        except Exception:
                            raw_req_headers = dict(getattr(req, "headers", None) or {})
                        merged = _merge_browser_route_headers(
                            raw_req_headers,
                            extra_headers,
                            override_names=operator_override_names,
                        )
                        route.continue_(headers=merged)
                    else:
                        route.continue_()

                if hasattr(context, "route_web_socket"):
                    context.route_web_socket("**/*", _on_websocket)
                context.route("**/*", _on_route)

                page = context.new_page()
                page.on(
                    "console",
                    lambda msg: _inc_console_error()
                    if str(getattr(msg, "type", "") or "").lower() == "error"
                    else None,
                )
                page.on("pageerror", lambda _err: _inc_console_error())

                resp = page.goto(full_url, wait_until="domcontentloaded", timeout=timeout_ms)
                if wait_ms > 0:
                    page.wait_for_timeout(wait_ms)

                final_raw_url = str(page.url or full_url)
                # Confirm the document stayed on the authorized origin before evaluating DOM.
                _resolve_and_check_scope(http, final_raw_url)

                status = int(resp.status) if resp is not None else 0
                raw_headers = resp.headers if resp is not None and isinstance(resp.headers, dict) else {}
                csp_value = ""
                for hk, hv in raw_headers.items():
                    if str(hk).lower() == "content-security-policy":
                        csp_value = str(hv or "").strip()
                        break

                try:
                    rt_payload = page.evaluate(_COLLECT_RUNTIME_JS)
                except Exception:
                    rt_payload = {"events": [], "state": {}, "dom_sinks": [], "postmessage_listeners": []}
                rt_events = rt_payload.get("events") if isinstance(rt_payload, dict) else []
                rt_dom_sinks = rt_payload.get("dom_sinks") if isinstance(rt_payload, dict) else []
                rt_pm_listeners = rt_payload.get("postmessage_listeners") if isinstance(rt_payload, dict) else []

                try:
                    dom_info = page.evaluate(_INSPECT_DOM_JS, marker)
                except Exception:
                    dom_info = {}

                return {
                    "ok": True,
                    "url": final_raw_url,
                    "status": status,
                    "title": str(dom_info.get("title") or "") if isinstance(dom_info, dict) else "",
                    "csp": csp_value,
                    "runtime_events": rt_events if isinstance(rt_events, list) else [],
                    "dom_sinks": rt_dom_sinks if isinstance(rt_dom_sinks, list) else [],
                    "postmessage_listeners": rt_pm_listeners if isinstance(rt_pm_listeners, list) else [],
                    "console_error_count": console_error_count,
                    "blocked_request_count": len(blocked_requests),
                    "marker_check": {
                        "checked": bool(dom_info.get("checked")) if isinstance(dom_info, dict) else False,
                        "in_inner_text": bool(dom_info.get("in_inner_text")) if isinstance(dom_info, dict) else False,
                        "in_outer_html": bool(dom_info.get("in_outer_html")) if isinstance(dom_info, dict) else False,
                        "in_script_or_event_attr": (
                            bool(dom_info.get("in_script_or_event_attr")) if isinstance(dom_info, dict) else False
                        ),
                        "script_matches": int(dom_info.get("script_matches") or 0) if isinstance(dom_info, dict) else 0,
                        "event_attr_matches": (
                            list(dom_info.get("event_attr_matches") or [])[:20] if isinstance(dom_info, dict) else []
                        ),
                    },
                }
            finally:
                context.close()
                browser.close()

    return _run_sync(_run, timeout=max(30.0, (timeout_ms / 1000.0) + 15.0))


def inspect_rendered_page(
    http: AgenticHTTPClient,
    *,
    url: str,
    actor: str = "anon",
    marker: str = "",
    wait_ms: int = 300,
    timeout_ms: int = 10000,
    runner: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Inspect a single rendered page in a strictly read-only, scope-locked Chromium context."""
    full_url = _resolve_and_check_scope(http, url)
    scope_guard = getattr(http, "scope_guard", None)
    base_parsed = urlsplit(http.base_url)
    base_scheme = base_parsed.scheme
    base_netloc = base_parsed.netloc
    compact_requested = (
        _compact_same_origin_url(
            full_url,
            base_url=http.base_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        or "/"
    )

    clean_actor = str(actor or "anon").strip() or "anon"
    cookie_hdr, extra_headers = _extract_actor_browser_auth(http, clean_actor)
    local_storage = _extract_actor_local_storage(http, clean_actor)
    local_storage_by_origin = _extract_actor_local_storage_by_origin(http, clean_actor)
    cookie_records = _extract_actor_cookie_records(
        http,
        clean_actor,
        base_url=http.base_url,
        fallback_cookie_hdr=cookie_hdr,
    )
    secrets = _collect_actor_secrets(
        http,
        cookie_hdr,
        extra_headers,
        local_storage=local_storage,
        cookie_records=cookie_records,
        local_storage_by_origin=local_storage_by_origin,
    )

    eff_wait_ms = max(0, min(int(wait_ms), _MAX_WAIT_MS))
    eff_timeout_ms = max(_MIN_TIMEOUT_MS, min(int(timeout_ms), _MAX_TIMEOUT_MS))
    clean_marker = str(marker or "")

    if _budget_remaining(http) <= 0:
        raise BudgetExhaustedError("campaign request budget exhausted")

    if runner is None and (not HAS_PLAYWRIGHT or _sync_playwright is None):
        return {
            "ok": False,
            "error": "playwright_unavailable",
        }

    allowed, reason = http.budget.consume()
    if not allowed:
        raise BudgetExhaustedError(reason)

    try:
        if runner is not None:
            runner_kwargs: dict[str, Any] = {
                "cookie": cookie_hdr,
                "marker": clean_marker,
                "wait_ms": eff_wait_ms,
                "timeout_ms": eff_timeout_ms,
            }
            if _fn_prefers_headers_kwarg(runner):
                runner_kwargs["headers"] = extra_headers
            else:
                runner_kwargs["extra_headers"] = extra_headers
            if local_storage and _fn_accepts_kwarg(runner, "local_storage"):
                runner_kwargs["local_storage"] = dict(local_storage)
            if local_storage_by_origin and _fn_accepts_kwarg(runner, "local_storage_by_origin"):
                runner_kwargs["local_storage_by_origin"] = {
                    k: dict(v) for k, v in local_storage_by_origin.items()
                }
            if cookie_records and _fn_accepts_kwarg(runner, "cookie_records"):
                runner_kwargs["cookie_records"] = [dict(c) for c in cookie_records]
            raw = runner(full_url, **runner_kwargs)
        else:
            raw = _inspect_rendered_page_playwright(
                http,
                full_url=full_url,
                cookie_hdr=cookie_hdr,
                extra_headers=extra_headers,
                local_storage=local_storage,
                local_storage_by_origin=local_storage_by_origin,
                cookie_records=cookie_records,
                marker=clean_marker,
                wait_ms=eff_wait_ms,
                timeout_ms=eff_timeout_ms,
            )
    except ScopeViolationError:
        return {
            "ok": False,
            "error": "off_origin_navigation",
            "url": compact_requested,
            "actor": clean_actor,
        }
    except Exception as exc:
        return {
            "ok": False,
            "error": _redact_secrets(f"{type(exc).__name__}: {str(exc)[:240]}", secrets),
            "url": compact_requested,
            "actor": clean_actor,
        }

    raw_dict = raw if isinstance(raw, dict) else {}
    if not raw_dict.get("ok"):
        return {
            "ok": False,
            "error": _redact_secrets(str(raw_dict.get("error") or "inspect_failed"), secrets)[:300],
            "url": compact_requested,
            "actor": clean_actor,
        }

    final_url = (
        _compact_same_origin_url(
            str(raw_dict.get("url") or full_url),
            base_url=http.base_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        or compact_requested
    )
    csp_raw = str(raw_dict.get("csp") or "").strip()
    csp_safe = _redact_secrets(csp_raw, secrets)[:512]
    title_safe = _redact_secrets(str(raw_dict.get("title") or "").strip(), secrets)[:180]

    raw_rt_source = raw_dict.get("runtime_requests")
    if raw_rt_source is None:
        raw_rt_source = raw_dict.get("runtime_events")
    runtime_requests = _sanitize_runtime_requests(
        raw_rt_source,
        base_url=full_url,
        base_scheme=base_scheme,
        base_netloc=base_netloc,
        scope_guard=scope_guard,
    )

    raw_marker_val = raw_dict.get("marker_check")
    raw_marker: dict[str, Any] = raw_marker_val if isinstance(raw_marker_val, dict) else {}
    marker_check = {
        "checked": bool(raw_marker.get("checked")) if raw_marker else bool(clean_marker),
        "in_inner_text": bool(raw_marker.get("in_inner_text")),
        "in_outer_html": bool(raw_marker.get("in_outer_html")),
        "in_script_or_event_attr": bool(raw_marker.get("in_script_or_event_attr")),
        "script_matches": int(raw_marker.get("script_matches") or 0),
        "event_attr_matches": [
            str(x)[:64] for x in (raw_marker.get("event_attr_matches") or []) if str(x).strip()
        ][:20],
    }

    dom_sinks = _sanitize_dom_sinks(raw_dict.get("dom_sinks"), secrets)
    postmessage_listeners = _sanitize_postmessage_listeners(raw_dict.get("postmessage_listeners"), secrets)

    return {
        "ok": True,
        "url": _redact_secrets(final_url, secrets),
        "actor": clean_actor,
        "status": int(raw_dict.get("status") or 0),
        "title": title_safe,
        "csp_present": bool(csp_safe),
        "csp": csp_safe,
        "runtime_requests": runtime_requests,
        "dom_sinks": dom_sinks,
        "postmessage_listeners": postmessage_listeners,
        "console_error_count": int(raw_dict.get("console_error_count") or 0),
        "blocked_request_count": int(raw_dict.get("blocked_request_count") or 0),
        "marker_check": marker_check,
    }


def _sanitize_dom_sinks(raw_sinks: Any, secrets: list[str]) -> list[dict[str, Any]]:
    normalized = (
        _normalize_dom_sinks(raw_sinks)
        if callable(_normalize_dom_sinks)
        else (raw_sinks if isinstance(raw_sinks, list) else [])
    )
    out: list[dict[str, Any]] = []
    for item in normalized:
        if not isinstance(item, dict):
            continue
        sink = str(item.get("sink") or "").strip()[:60]
        if not sink:
            continue
        out.append({
            "sink": sink,
            "tag": str(item.get("tag") or "").strip().lower()[:40],
            "snippet": _redact_secrets(str(item.get("snippet") or ""), secrets)[:200],
            "source_matches": [
                str(s)[:40] for s in (item.get("source_matches") or []) if str(s).strip()
            ][:8],
        })
        if len(out) >= 40:
            break
    return out


def _sanitize_postmessage_listeners(raw_listeners: Any, secrets: list[str]) -> list[dict[str, Any]]:
    normalized = (
        _normalize_postmessage_listeners(raw_listeners)
        if callable(_normalize_postmessage_listeners)
        else (raw_listeners if isinstance(raw_listeners, list) else [])
    )
    out: list[dict[str, Any]] = []
    for item in normalized:
        if not isinstance(item, dict):
            continue
        out.append({
            "type": str(item.get("type") or "addEventListener").strip()[:40],
            "has_origin_check": bool(item.get("has_origin_check")),
            "handler_preview": _redact_secrets(str(item.get("handler_preview") or ""), secrets)[:240],
        })
        if len(out) >= 20:
            break
    return out


def _build_dom_probe_url(full_url: str, *, source: str, param_name: str, canary: str) -> str:
    parsed = urlsplit(full_url)
    if source == "hash":
        encoded = quote(canary, safe="")
        frag = f"{param_name}={encoded}" if param_name else encoded
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, frag))
    if source == "query":
        pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
        key = str(param_name or "q").strip() or "q"
        pairs.append((key, canary))
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(pairs), parsed.fragment))
    return full_url


def verify_dom_sink_in_browser(
    http: AgenticHTTPClient,
    *,
    url: str,
    actor: str = "anon",
    source: str = "hash",
    param_name: str = "",
    canary: str = '<span data-kryon-dom-canary="1"></span>',
    wait_ms: int = 250,
    timeout_ms: int = 8000,
) -> dict[str, Any]:
    """Deterministically verify whether a benign DOM canary is parsed into live DOM in an isolated read-only browser."""
    clean_source = str(source or "hash").strip().lower()
    if clean_source not in {"hash", "query", "postmessage"}:
        raise ValueError(f"Unsupported DOM verification source: {source!r}")

    full_url = _resolve_and_check_scope(http, url)
    scope_guard = getattr(http, "scope_guard", None)
    base_parsed = urlsplit(http.base_url)
    base_scheme = base_parsed.scheme
    base_netloc = base_parsed.netloc

    probe_url = _build_dom_probe_url(
        full_url,
        source=clean_source,
        param_name=param_name if clean_source != "query" else (param_name or "q"),
        canary=canary,
    )
    _resolve_and_check_scope(http, probe_url)

    clean_actor = str(actor or "anon").strip() or "anon"
    cookie_hdr, extra_headers = _extract_actor_browser_auth(http, clean_actor)
    local_storage = _extract_actor_local_storage(http, clean_actor)
    local_storage_by_origin = _extract_actor_local_storage_by_origin(http, clean_actor)
    cookie_records = _extract_actor_cookie_records(
        http,
        clean_actor,
        base_url=http.base_url,
        fallback_cookie_hdr=cookie_hdr,
    )
    secrets = _collect_actor_secrets(
        http,
        cookie_hdr,
        extra_headers,
        local_storage=local_storage,
        cookie_records=cookie_records,
        local_storage_by_origin=local_storage_by_origin,
    )

    eff_wait_ms = max(0, min(int(wait_ms), _MAX_WAIT_MS))
    eff_timeout_ms = max(_MIN_TIMEOUT_MS, min(int(timeout_ms), _MAX_TIMEOUT_MS))

    if _budget_remaining(http) <= 0:
        raise BudgetExhaustedError("campaign request budget exhausted")

    if not HAS_PLAYWRIGHT or _sync_playwright is None:
        return {
            "ok": False,
            "verified_dom_injection": False,
            "dom_element_parsed": False,
            "matched_sinks": [],
            "postmessage_listeners": [],
            "source": clean_source,
            "url": _redact_secrets(probe_url, secrets),
            "actor": clean_actor,
            "error": "playwright_unavailable",
        }

    allowed, reason = http.budget.consume()
    if not allowed:
        raise BudgetExhaustedError(reason)

    def _run() -> dict[str, Any]:
        assert _sync_playwright is not None
        operator_override_names = frozenset(k.lower() for k in _operator_browser_headers(http))
        with _sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
            context = browser.new_context(
                ignore_https_errors=True,
                service_workers="block",
                user_agent=_operator_user_agent(http),
            )
            try:
                ls_init = _build_multi_origin_localstorage_init_script(
                    local_storage_by_origin,
                    fallback_origin=http.base_url,
                    fallback_local_storage=local_storage,
                )
                if ls_init:
                    context.add_init_script(ls_init)
                if callable(_build_runtime_hook_script):
                    context.add_init_script(_build_runtime_hook_script())
                if cookie_records:
                    context.add_cookies([dict(c) for c in cookie_records])
                else:
                    cookie_pairs = _parse_cookie_pairs(cookie_hdr)
                    if cookie_pairs:
                        context.add_cookies([
                            {"name": cname, "value": cval, "url": http.base_url}
                            for cname, cval in cookie_pairs
                        ])

                async def _on_websocket(socket: Any) -> None:
                    route_obj = getattr(socket, "_impl_obj", socket)
                    closing = route_obj.close(code=1008, reason="readonly dom verifier: websocket blocked")
                    if inspect.isawaitable(closing):
                        await closing

                def _on_route(route: Any) -> None:
                    req = route.request
                    req_method = str(getattr(req, "method", "GET") or "GET").strip().upper()
                    req_url = str(getattr(req, "url", "") or "")
                    if req_method not in {"GET", "HEAD"}:
                        route.abort("blockedbyclient")
                        return
                    try:
                        _resolve_and_check_scope(http, req_url)
                    except ScopeViolationError:
                        route.abort("blockedbyclient")
                        return
                    if extra_headers:
                        try:
                            raw_req_headers = dict(req.all_headers() or {})
                        except Exception:
                            raw_req_headers = dict(getattr(req, "headers", None) or {})
                        merged = _merge_browser_route_headers(
                            raw_req_headers,
                            extra_headers,
                            override_names=operator_override_names,
                        )
                        route.continue_(headers=merged)
                    else:
                        route.continue_()

                if hasattr(context, "route_web_socket"):
                    context.route_web_socket("**/*", _on_websocket)
                context.route("**/*", _on_route)

                page = context.new_page()
                page.goto(probe_url, wait_until="domcontentloaded", timeout=eff_timeout_ms)
                if eff_wait_ms > 0:
                    page.wait_for_timeout(eff_wait_ms)

                if clean_source == "postmessage":
                    page.evaluate(
                        "(payload) => window.postMessage(payload, window.location.origin)",
                        canary,
                    )
                    page.wait_for_timeout(max(150, eff_wait_ms))

                final_raw_url = str(page.url or probe_url)
                _resolve_and_check_scope(http, final_raw_url)

                dom_parsed = bool(page.evaluate(_CHECK_DOM_CANARY_JS, "data-kryon-dom-canary"))
                try:
                    rt_payload = page.evaluate(_COLLECT_RUNTIME_JS)
                except Exception:
                    rt_payload = {"dom_sinks": [], "postmessage_listeners": []}
                return {
                    "ok": True,
                    "url": final_raw_url,
                    "dom_element_parsed": dom_parsed,
                    "dom_sinks": rt_payload.get("dom_sinks") if isinstance(rt_payload, dict) else [],
                    "postmessage_listeners": (
                        rt_payload.get("postmessage_listeners") if isinstance(rt_payload, dict) else []
                    ),
                }
            finally:
                context.close()
                browser.close()

    try:
        raw = _run_sync(_run, timeout=max(30.0, (eff_timeout_ms / 1000.0) + 15.0))
    except ScopeViolationError:
        return {
            "ok": False,
            "verified_dom_injection": False,
            "dom_element_parsed": False,
            "matched_sinks": [],
            "postmessage_listeners": [],
            "source": clean_source,
            "url": _redact_secrets(probe_url, secrets),
            "actor": clean_actor,
            "error": "off_origin_navigation",
        }
    except Exception as exc:
        return {
            "ok": False,
            "verified_dom_injection": False,
            "dom_element_parsed": False,
            "matched_sinks": [],
            "postmessage_listeners": [],
            "source": clean_source,
            "url": _redact_secrets(probe_url, secrets),
            "actor": clean_actor,
            "error": _redact_secrets(f"{type(exc).__name__}: {str(exc)[:240]}", secrets),
        }

    sinks = _sanitize_dom_sinks(raw.get("dom_sinks"), secrets)
    listeners = _sanitize_postmessage_listeners(raw.get("postmessage_listeners"), secrets)
    dom_element_parsed = bool(raw.get("dom_element_parsed"))
    final_url = (
        _compact_same_origin_url(
            str(raw.get("url") or probe_url),
            base_url=http.base_url,
            base_scheme=base_scheme,
            base_netloc=base_netloc,
            allow_fragment_route=True,
            scope_guard=scope_guard,
        )
        or probe_url
    )
    return {
        "ok": True,
        "verified_dom_injection": dom_element_parsed,
        "dom_element_parsed": dom_element_parsed,
        "matched_sinks": sinks,
        "postmessage_listeners": listeners,
        "source": clean_source,
        "url": _redact_secrets(final_url, secrets),
        "actor": clean_actor,
        "error": "",
    }


__all__ = [
    "CHROMIUM_ARGS",
    "HAS_PLAYWRIGHT",
    "_build_multi_origin_localstorage_init_script",
    "_build_origin_localstorage_init_script",
    "_extract_actor_browser_auth",
    "_extract_actor_cookie_records",
    "_extract_actor_local_storage",
    "_extract_actor_local_storage_by_origin",
    "_merge_browser_route_headers",
    "_operator_browser_headers",
    "_operator_user_agent",
    "inspect_rendered_page",
    "run_browser_crawl",
    "verify_dom_sink_in_browser",
]
