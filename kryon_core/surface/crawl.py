"""Playwright BFS crawl + XHR capture → surface-shaped JSON (optional dep)."""

from __future__ import annotations

import asyncio
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

from kryon_core.browser.policy import install_readonly_request_gate

from .extract import extract_css, extract_http_headers
from .parsers import parse_browser_crawl

try:
    from playwright.sync_api import sync_playwright  # type: ignore

    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

PLAYWRIGHT_MSG = (
    "HATA: playwright kurulu değil.\n"
    "Kurulum:\n  pip install playwright\n  playwright install chromium"
)

SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3",
    ".pdf", ".zip", ".tar", ".gz",
)


CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]


def playwright_missing_msg() -> str:
    return PLAYWRIGHT_MSG


def run_playwright_sync(fn, timeout: float = 180):
    """Run Playwright Sync API off an active asyncio event loop.

    sync_playwright() raises if a loop is already running:
    'It looks like you are using Playwright Sync API inside the asyncio loop.'
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pw-sync") as pool:
        return pool.submit(fn).result(timeout=timeout)


def _is_non_static_url(url: str) -> bool:
    path = urlparse(str(url or "")).path.lower()
    return not any(path.endswith(ext) for ext in SKIP_EXT)


def _is_enqueueable(url: str) -> bool:
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXT):
        return False
    if path.endswith((".js", ".mjs")):
        return False
    return True


_COLLECT_DOM_JS = r"""() => {
  const links = [];
  const scripts = [];
  const hashes = [];
  const forms = [];
  const walk = (root) => {
    if (!root || !root.querySelectorAll) return;
    const pushUrl = (raw, isScript) => {
      const val = String(raw || '').trim();
      if (!val) return;
      const low = val.toLowerCase();
      if (
        low.startsWith('javascript:')
        || low.startsWith('mailto:')
        || low.startsWith('data:')
        || low.startsWith('blob:')
        || low.startsWith('tel:')
      ) {
        return;
      }
      if (val.startsWith('#/')) {
        hashes.push(val);
        return;
      }
      if (val.startsWith('#')) return;
      if (isScript) scripts.push(val);
      else links.push(val);
    };
    const attrs = [
      ['a[href]', 'href', false],
      ['area[href]', 'href', false],
      ['link[href]', 'href', false],
      ['script[src]', 'src', true],
      ['iframe[src]', 'src', false],
      ['frame[src]', 'src', false],
      ['embed[src]', 'src', false],
      ['object[data]', 'data', false],
      ['source[src]', 'src', false],
      ['video[src]', 'src', false],
      ['audio[src]', 'src', false],
      ['video[poster]', 'poster', false],
      ['img[longdesc]', 'longdesc', false],
      ['img[lowsrc]', 'lowsrc', false],
      ['form[action]', 'action', false],
      ['button[formaction]', 'formaction', false],
      ['[cite]', 'cite', false],
      ['[ng-href]', 'ng-href', false],
    ];
    for (const [sel, attr, isScript] of attrs) {
      for (const el of root.querySelectorAll(sel)) {
        pushUrl(el.getAttribute(attr), isScript);
      }
    }
    for (const el of root.querySelectorAll('[xlink\\:href]')) {
      pushUrl(
        el.getAttribute('xlink:href')
          || (el.getAttributeNS ? el.getAttributeNS('http://www.w3.org/1999/xlink', 'href') : ''),
        false
      );
    }
    for (const el of root.querySelectorAll('img[srcset], source[srcset]')) {
      const raw = String(el.getAttribute('srcset') || '');
      for (const part of raw.split(',')) {
        const candidate = part.trim().split(/\s+/)[0];
        if (candidate) pushUrl(candidate, false);
      }
    }
    for (const el of root.querySelectorAll('[ping]')) {
      const raw = String(el.getAttribute('ping') || '');
      for (const tok of raw.trim().split(/\s+/)) {
        if (tok) pushUrl(tok, false);
      }
    }
    for (const form of root.querySelectorAll('form')) {
      const fields = [];
      for (const inp of form.querySelectorAll('input, textarea, select')) {
        const name = inp.getAttribute('name') || '';
        if (!name) continue;
        const typ = inp.getAttribute('type') || 'text';
        const val = typ.toLowerCase() === 'password' ? '' : (inp.getAttribute('value') || '');
        fields.push({name, type: typ, value: val});
      }
      forms.push({
        action: form.getAttribute('action') || '',
        method: (form.getAttribute('method') || 'GET').toUpperCase(),
        enctype: form.getAttribute('enctype') || '',
        fields,
      });
    }
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);
  return {links, scripts, hashes, forms};
}"""


_CLICK_SAFE_INTERACTIVE_JS = r"""() => {
  const destructive = /delete|remove|logout|sign.?out|purchase|pay|reset|revoke|destroy/i;
  const clicked = window.__ccoSafeClicked || (window.__ccoSafeClicked = new WeakSet());
  const nonSubmit = [];
  const submitCandidates = [];
  const walk = (root) => {
    if (!root || !root.querySelectorAll) return;
    for (const el of root.querySelectorAll('button, input[type="button"], input[type="submit"], [onclick], [ng-click]')) {
      if (clicked.has(el)) continue;
      if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;
      if (el.getAttribute('href')) continue;
      if (el.getAttribute('role') === 'tab' || el.hasAttribute('aria-controls')) continue;
      const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : {width: 0, height: 0};
      if (!rect.width || !rect.height) continue;
      const hay = [
        el.textContent || '',
        el.id || '',
        el.getAttribute('name') || '',
        el.getAttribute('aria-label') || '',
        el.getAttribute('value') || '',
        el.getAttribute('onclick') || '',
        el.getAttribute('ng-click') || '',
      ].join(' ');
      if (destructive.test(hay)) continue;
      const tag = (el.tagName || '').toLowerCase();
      const typ = (el.getAttribute('type') || '').toLowerCase();
      const isNativeSubmit = (
        (tag === 'input' && typ === 'submit')
        || (tag === 'button' && typ === 'submit' && !!el.closest('form')
            && !el.hasAttribute('onclick') && !el.hasAttribute('ng-click'))
      );
      if (isNativeSubmit) submitCandidates.push(el);
      else nonSubmit.push(el);
    }
    for (const el of root.querySelectorAll('*')) {
      if (el.shadowRoot) walk(el.shadowRoot);
    }
  };
  walk(document);
  const target = nonSubmit[0] || submitCandidates[0] || null;
  if (!target) return {clicked: false};
  clicked.add(target);
  const label = (
    target.id
    || target.getAttribute('aria-label')
    || target.textContent
    || target.tagName
    || ''
  ).trim().slice(0, 80);
  target.click();
  return {clicked: true, control: label || 'button'};
}"""


def _click_safe_interactive(
    page,
    frontier,
    max_actions: int,
    harvest,
    ensure_active,
    wait_ms: int = 0,
    metadata_fn=None,
) -> int:
    """Click a bounded slice of safe non-destructive triggers (including Shadow DOM)."""
    budget = min(8, max(0, int(max_actions)))
    if budget <= 0:
        return 0
    used = 0
    start_url = page.url
    meta_page = metadata_fn(start_url) if callable(metadata_fn) else start_url
    for _ in range(budget):
        ensure_active()
        try:
            res = page.evaluate(_CLICK_SAFE_INTERACTIVE_JS)
        except Exception:
            break
        if not isinstance(res, dict) or not res.get("clicked"):
            break
        used += 1
        settle_ms = max(25, min(int(wait_ms or 0), 150))
        page.wait_for_timeout(settle_ms)
        ensure_active()
        operations = harvest()
        if operations:
            frontier.features.append({
                "page": meta_page,
                "identity": frontier.identity,
                "action": "click",
                "control": str(res.get("control") or "button"),
                "operations": list(dict.fromkeys(operations)),
                "operation_yield": len(set(operations)),
            })
        if page.url != start_url:
            frontier.add(page.url, source="runtime-click", kind="page")
            break
    return used


def _parse_header_blob(headers) -> dict:
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items() if k}
    extra = {}
    for line in str(headers).splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name:
            extra[name] = value.strip()
    return extra


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme, parsed.hostname.lower(), port) if port > 0 else None
    except ValueError:
        return None


class _WireGateScope:
    """Scope adapter backed solely by a caller-provided read-only wire_gate."""

    def __init__(self, gate: Any, start_url: str) -> None:
        self._gate = gate
        self._origin = _origin(start_url)

    def permits_url(self, url: str) -> bool:
        if not self._origin or _origin(url) != self._origin:
            return False
        try:
            allowed, _reason = self._gate("GET", url, {})
            return bool(allowed)
        except Exception:
            return False


class _GateAdapter:
    def __init__(self, gate: Any) -> None:
        self.gate = gate
        self.accounts_campaign_requests = getattr(gate, "accounts_campaign_requests", False)

    def validate_wire_invocation(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        allowed, reason = self.gate(args["method"], args["url"], args.get("headers") or {})
        return {"allowed": bool(allowed), "reason": str(reason or "blocked")}


class _SessionGateAdapter:
    """Recheck the exact checked secret version before every browser request."""

    def __init__(self, engine: Any, target: str, identity: str, session: dict[str, Any], session_store_mod: Any) -> None:
        self.engine, self.target, self.identity, self.session = engine, target, identity, session
        self._session_store = session_store_mod
        self.accounts_campaign_requests = getattr(engine, "accounts_campaign_requests", False)
        self.stopped = ""

    def stop_reason(self) -> str:
        return self.stopped

    def validate_wire_invocation(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        if _origin(args.get("url", "")) != _origin(self.target):
            return {"allowed": False, "reason": "crawl request outside session origin"}
        if self.stopped or not self._session_store.same_verified_session(self.target, self.identity, self.session):
            self.stopped = "crawl session changed or expired"
            return {"allowed": False, "reason": "crawl session changed, expired or outside origin"}
        return self.engine.validate_wire_invocation(tool_name, args)


def crawl_site(
    url: str,
    max_pages: int = 40,
    cookie: str = "",
    headers=None,
    timeout_ms: int = 15000,
    allow_subdomains: bool = False,
    wait_ms: int = 400,
    wire_gate=None,
    tool_name: str = "kali-tools_crawl_web_surface",
    session_target: str = "",
    identity: str = "",
    source_records=None,
    max_actions: int = 40,
) -> dict:
    """Read-only BFS with a gate on every same-origin browser request."""
    start = (url or "").strip()
    if not start:
        return {"ok": False, "error": "url gerekli", "records": [], "pages": [], "xhr": []}
    if not start.startswith(("http://", "https://")):
        start = "https://" + start
    if not HAS_PLAYWRIGHT:
        return {
            "ok": False,
            "error": PLAYWRIGHT_MSG,
            "url": start,
            "records": [],
            "pages": [],
            "xhr": [],
        }

    scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
    if scripts_dir.is_dir() and str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    try:
        if not _origin(start):
            raise ValueError("crawl start URL is outside active scope")
        if wire_gate is not None:
            if not callable(wire_gate):
                raise ValueError("crawl request gate is unavailable")
            scope: Any = _WireGateScope(wire_gate, start)
            if not scope.permits_url(start):
                raise ValueError("crawl start URL is outside active scope")
            engine: Any = _GateAdapter(wire_gate)
        else:
            raise ValueError("crawl wire_gate is required")
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        return {
            "ok": False,
            "error": f"crawl policy unavailable: {type(exc).__name__}",
            "url": start,
            "records": [],
            "pages": [],
            "xhr": [],
        }

    extra_headers = _parse_header_blob(headers)
    if session_target or identity:
        return {"ok": False, "error": "crawl session store unavailable"}
    if cookie and "Cookie" not in extra_headers and "cookie" not in extra_headers:
        extra_headers["Cookie"] = cookie
    handle = os.environ.get("HACKERONE_HANDLE", "").strip()
    header_name = os.environ.get("CCO_RESEARCH_HEADER", "X-HackerOne-Research").strip()
    if handle and header_name and not any(str(k).lower() == header_name.lower() for k in extra_headers):
        extra_headers[header_name] = handle

    def _run():
        return _crawl_site_sync(
            start, max_pages, extra_headers, timeout_ms, allow_subdomains, wait_ms,
            scope, engine, tool_name, install_readonly_request_gate, wire_gate,
            identity=identity or ("authenticated" if cookie or extra_headers.get("Authorization") else "anonymous"),
            source_records=source_records, max_actions=max_actions,
        )

    try:
        return run_playwright_sync(_run)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"crawl failed: {type(exc).__name__}" if identity else str(exc)[:400],
            "url": start,
            "records": [],
            "pages": [],
            "xhr": [],
        }


def _crawl_site_sync(
    start, max_pages, extra_headers, timeout_ms, allow_subdomains, wait_ms,
    scope, engine, tool_name, install_gate, wire_gate, identity="anonymous",
    source_records=None, max_actions=40,
):
    captured: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    links: list[str] = []
    hash_routes: list[str] = []
    js_files: list[str] = []
    asset_texts: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    from .frontier import UnifiedFrontier, metadata_url
    from .crawl_auth import CrawlAuthBoundary
    from .feature_crawl import explore_features
    frontier = UnifiedFrontier(start, scope.permits_url, identity)
    frontier.add(start, source="entry-point")
    frontier.add_records(source_records or [])
    auth = CrawlAuthBoundary(
        getattr(engine, "session", {}).get("check_url", start),
        authenticated=identity != "anonymous",
    )
    visited: set[str] = set()
    action_budget = max(0, int(max_actions))

    origin = _origin(start)

    def permitted(url):
        return _origin(url) == origin and scope.permits_url(url)

    def _safe_body_fields(post_data: str | None, ctype: str) -> list[str]:
        if not post_data or not isinstance(post_data, str):
            return []
        try:
            from .serialization import body_parameters
            return [
                str(p["name"])
                for p in body_parameters(post_data, ctype)
                if isinstance(p, dict) and p.get("name")
            ][:32]
        except Exception:
            return []

    seen_forms: set[tuple[Any, ...]] = set()
    captured_css_urls: set[str] = set()

    def _add_form_entry(page_url: str, action: str, method: str, enctype: str, raw_fields) -> None:
        if not permitted(action):
            return
        norm_method = (method or "GET").upper()
        norm_enctype = (enctype or "").split(";", 1)[0].strip().lower()
        content_type = ""
        if norm_method != "GET":
            content_type = norm_enctype or "application/x-www-form-urlencoded"
        fields: list[dict[str, Any]] = []
        sig_fields = []
        for raw_f in raw_fields or []:
            if not isinstance(raw_f, dict):
                continue
            name = str(raw_f.get("name") or "")
            if not name:
                continue
            typ = str(raw_f.get("type") or "text")
            field_item: dict[str, Any] = {"name": name, "type": typ}
            if typ.lower() != "password":
                raw_val = str(raw_f.get("value") or "")
                if raw_val:
                    from .normalize import safe_sample
                    sampled = safe_sample(name, raw_val)
                    if sampled and sampled != "<redacted>":
                        field_item["value"] = sampled
            fields.append(field_item)
            sig_fields.append((name, typ))
        sig = (page_url, action, norm_method, tuple(sig_fields))
        if sig in seen_forms:
            return
        seen_forms.add(sig)
        form_entry: dict[str, Any] = {
            "page": page_url,
            "action": action,
            "method": norm_method,
            "fields": fields,
        }
        if content_type:
            form_entry["content_type"] = content_type
        forms.append(form_entry)

    def _record_xhr_request(req, status: int = 0) -> None:
        req_method = str(getattr(req, "method", "GET") or "GET").upper()
        req_type = str(getattr(req, "resource_type", "") or "").lower()
        req_url = str(getattr(req, "url", "") or "")
        if (
            req_type in ("xhr", "fetch", "eventsource")
            and req_method in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"}
            and req_url
            and permitted(req_url)
        ):
            cur_page = metadata_url(page.url)
            for existing in captured:
                if (
                    existing.get("method") == req_method
                    and existing.get("url") == req_url
                    and existing.get("identity") == identity
                    and existing.get("page") == cur_page
                ):
                    if status and not existing.get("status"):
                        existing["status"] = status
                    return
            item: dict[str, Any] = {
                "method": req_method,
                "url": req_url,
                "resource_type": req_type,
                "identity": identity,
                "page": cur_page,
                "status": status,
            }
            headers_map: dict[str, Any] = {}
            try:
                headers_map = req.headers or {}
            except Exception:
                headers_map = {}
            ctype = headers_map.get("content-type") or headers_map.get("Content-Type") or ""
            if ctype:
                item["content_type"] = ctype
            if req_method in {"POST", "PUT", "PATCH"}:
                try:
                    post_data = req.post_data
                except Exception:
                    post_data = None
                fields = _safe_body_fields(post_data, str(ctype))
                if fields:
                    item["body_fields"] = fields
            captured.append(item)
            frontier.add(req_url, source="runtime-xhr", kind="operation", method=req_method)

    def _on_request(req):
        try:
            req_method = str(getattr(req, "method", "GET") or "GET").upper()
            if req_method in {"POST", "PUT", "PATCH"}:
                _record_xhr_request(req, status=0)
        except Exception:
            pass

    def _on_response(resp):
        try:
            req = resp.request
            req_method = str(getattr(req, "method", "GET") or "GET").upper()
            req_type = str(getattr(req, "resource_type", "") or "").lower()
            req_url = str(getattr(req, "url", "") or "")
            resp_url = str(getattr(resp, "url", "") or req_url)
            resp_status = int(getattr(resp, "status", 0) or 0)

            try:
                resp_headers = resp.headers or {}
            except Exception:
                resp_headers = {}

            if resp_headers and resp_url and permitted(resp_url):
                for rec in extract_http_headers(resp_headers, resp_url):
                    hdr_url = str(rec.get("url") or "")
                    if hdr_url and permitted(hdr_url) and _is_non_static_url(hdr_url):
                        frontier.add(
                            hdr_url,
                            source="runtime-header",
                            kind="page" if _is_enqueueable(hdr_url) else "bundle",
                            method=str(rec.get("method") or "GET").upper(),
                        )
                        links.append(hdr_url)

            resp_ctype = str(
                resp_headers.get("content-type") or resp_headers.get("Content-Type") or ""
            ).split(";", 1)[0].strip().lower()
            resp_path = urlsplit(resp_url).path.lower() if resp_url else ""
            if (
                resp_url
                and permitted(resp_url)
                and 200 <= resp_status < 400
                and ("css" in resp_ctype or resp_path.endswith(".css") or req_type == "stylesheet")
            ):
                try:
                    css_text = resp.text()
                except Exception:
                    css_text = ""
                if isinstance(css_text, str) and css_text:
                    if resp_url not in captured_css_urls:
                        captured_css_urls.add(resp_url)
                        asset_texts.append({
                            "url": resp_url,
                            "content_type": resp_ctype or "text/css",
                            "text": css_text[:200_000],
                        })
                    for rec in extract_css(css_text, resp_url, limit=120):
                        css_u = str(rec.get("url") or "")
                        if css_u and permitted(css_u) and _is_non_static_url(css_u):
                            frontier.add(
                                css_u,
                                source="runtime-css",
                                kind="page" if _is_enqueueable(css_u) else "bundle",
                            )
                            links.append(css_u)

            if req_type in ("xhr", "fetch", "eventsource") and req_method in {
                "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH"
            }:
                _record_xhr_request(req, status=resp_status)
            elif req_type == "script":
                frontier.add(req_url, source="runtime-bundle", kind="bundle")
                if permitted(req_url):
                    js_files.append(req_url)
            elif req_type == "document":
                if req_url and permitted(req_url) and _is_non_static_url(req_url):
                    frontier.add(
                        req_url,
                        source="runtime-document",
                        kind="page" if _is_enqueueable(req_url) else "bundle",
                    )
                    links.append(req_url)
            elif (
                req_type not in {"image", "media", "font", "stylesheet"}
                and req_url
                and permitted(req_url)
                and _is_non_static_url(req_url)
            ):
                frontier.add(
                    req_url,
                    source="runtime-network",
                    kind="page" if _is_enqueueable(req_url) else "bundle",
                    method=req_method,
                )
                links.append(req_url)
        except Exception:
            pass

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
        context_kwargs: dict[str, Any] = {
            "ignore_https_errors": True,
            "service_workers": "block",
            "user_agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        context = browser.new_context(**context_kwargs)
        try:
            cookie = next((v for k, v in extra_headers.items() if str(k).lower() == "cookie"), "")
            excluded = {
                "cookie", "host", "origin", "referer", "content-length", "connection",
                "transfer-encoding", "proxy-authorization", "user-agent",
            }
            safe_headers = {str(k): str(v) for k, v in extra_headers.items() if str(k).lower() not in excluded}

            def stopped(reason):
                observer = getattr(wire_gate, "observe", None)
                if callable(observer):
                    status = {"http_401": 401, "http_429": 429, "login_redirect": 302}.get(reason)
                    if status:
                        observer(
                            extra_headers,
                            {"ok": True, "status": status, "location": "/login" if reason == "login_redirect" else ""},
                        )

            state = install_gate(
                context,
                engine,
                tool_name,
                header_provider=lambda url: safe_headers if permitted(url) else {},
                request_filter=lambda url, headers: permitted(url),
                on_stop=stopped,
                auth_boundary=auth if isinstance(engine, _SessionGateAdapter) or identity == "anonymous" else None,
            )
            if cookie:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(cookie)
                if not parsed_cookie:
                    raise ValueError("crawl session cookie cannot be parsed")
                parsed = urlsplit(start)
                origin_url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
                context.add_cookies([
                    {"name": name, "value": morsel.value, "url": origin_url}
                    for name, morsel in parsed_cookie.items()
                ])
            page = context.new_page()
            page.on("request", _on_request)
            page.on("response", _on_response)

            def ensure_active():
                reason = auth.resolve(None)
                if reason:
                    state.update(stopped=True, reason=reason)
                    stopped(reason)
                if state.get("stopped") or getattr(engine, "stop_reason", lambda: "")():
                    raise RuntimeError("crawl stopped")
                if not permitted(page.url):
                    raise ValueError("crawl navigated outside allowed scope")

            def collect():
                frag = urlsplit(page.url).fragment
                if frag.startswith("/"):
                    hash_url = urljoin(start, frag)
                    if permitted(hash_url):
                        hash_routes.append(hash_url)
                try:
                    dom_data = page.evaluate(_COLLECT_DOM_JS)
                except Exception:
                    dom_data = None
                if isinstance(dom_data, dict):
                    for raw_h in dom_data.get("hashes") or []:
                        h_str = str(raw_h or "").strip()
                        if h_str.startswith("#/"):
                            hash_url = urljoin(start, h_str[1:])
                            if permitted(hash_url):
                                hash_routes.append(hash_url)
                    for raw_link in dom_data.get("links") or []:
                        absolute = urljoin(page.url, str(raw_link or ""))
                        if _is_enqueueable(absolute):
                            frontier.add(absolute, source="runtime-link", kind="page")
                        elif absolute.lower().endswith((".js", ".mjs")):
                            frontier.add(absolute, source="runtime-bundle", kind="bundle")
                        if permitted(absolute):
                            links.append(absolute)
                    for raw_script in dom_data.get("scripts") or []:
                        absolute = urljoin(page.url, str(raw_script or ""))
                        frontier.add(absolute, source="runtime-bundle", kind="bundle")
                        if permitted(absolute):
                            js_files.append(absolute)
                    for raw_form in dom_data.get("forms") or []:
                        if not isinstance(raw_form, dict):
                            continue
                        action = urljoin(page.url, str(raw_form.get("action") or "") or page.url)
                        _add_form_entry(
                            page.url,
                            action,
                            str(raw_form.get("method") or "GET"),
                            str(raw_form.get("enctype") or ""),
                            raw_form.get("fields") or [],
                        )
                    return

                for anchor in page.query_selector_all("a[href]"):
                    href = anchor.get_attribute("href") or ""
                    if not href or href.startswith(("javascript:", "mailto:", "data:")):
                        continue
                    if href.startswith("#/"):
                        hash_url = urljoin(start, href[1:])
                        if permitted(hash_url):
                            hash_routes.append(hash_url)
                        continue
                    absolute = urljoin(page.url, href)
                    frontier.add(absolute, source="runtime-link", kind="page" if _is_enqueueable(absolute) else "bundle")
                    if permitted(absolute):
                        links.append(absolute)
                for script in page.query_selector_all("script[src]"):
                    absolute = urljoin(page.url, script.get_attribute("src") or "")
                    frontier.add(absolute, source="runtime-bundle", kind="bundle")
                    if permitted(absolute):
                        js_files.append(absolute)

            while frontier.pending("page") and len(visited) < max(1, int(max_pages)):
                work = frontier.take("page")
                if work is None:
                    break
                current = work["url"]
                if current in visited:
                    continue
                if not permitted(current):
                    continue
                visited.add(current)
                resp = None
                try:
                    resp = page.goto(current, wait_until="domcontentloaded", timeout=timeout_ms)
                    if wait_ms:
                        page.wait_for_timeout(int(wait_ms))
                    ensure_active()
                    if not permitted(page.url):
                        raise ValueError("crawl navigated outside allowed origin or scope")
                    status = resp.status if resp else 0
                    title = ""
                    try:
                        title = page.title() or ""
                    except Exception:
                        title = ""
                    pages.append({
                        "url": current,
                        "status": status,
                        "title": title[:180],
                        "identity": identity,
                        **(
                            {
                                "content_type": (
                                    (resp.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
                                )
                            }
                            if resp and (resp.headers.get("content-type") or "").strip()
                            else {}
                        ),
                    })
                    if resp is not None and 200 <= status < 300:
                        resp_ctype = (resp.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
                        cur_path = urlsplit(current).path.lower()
                        if (
                            "javascript" in resp_ctype
                            or resp_ctype == "application/ecmascript"
                            or "json" in resp_ctype
                            or cur_path.endswith((".js", ".mjs", ".json"))
                        ):
                            try:
                                body_text = resp.text()
                            except Exception:
                                body_text = ""
                            if isinstance(body_text, str) and body_text:
                                asset_texts.append({
                                    "url": current,
                                    "content_type": resp_ctype,
                                    "text": body_text[:200_000],
                                })
                    frontier.finish(work)
                    collect()
                    capture_index = [len(captured)]

                    def feature_harvest():
                        collect()
                        new = captured[capture_index[0]:]
                        capture_index[0] = len(captured)
                        return [item["method"] + " " + metadata_url(item["url"]) for item in new]

                    action_budget -= explore_features(
                        page, frontier, action_budget, feature_harvest, ensure_active, wait_ms
                    )
                    action_budget -= _click_safe_interactive(
                        page,
                        frontier,
                        action_budget,
                        feature_harvest,
                        ensure_active,
                        wait_ms,
                        metadata_fn=metadata_url,
                    )

                    for form in page.query_selector_all("form"):
                        action = urljoin(page.url, form.get_attribute("action") or page.url)
                        raw_fields = []
                        for inp in form.query_selector_all("input, textarea, select"):
                            raw_fields.append({
                                "name": inp.get_attribute("name") or "",
                                "type": inp.get_attribute("type") or "text",
                                "value": inp.get_attribute("value") or "",
                            })
                        _add_form_entry(
                            current,
                            action,
                            form.get_attribute("method") or "GET",
                            form.get_attribute("enctype") or "",
                            raw_fields,
                        )

                except Exception as exc:
                    errors.append({"url": current, "error": str(exc)[:160]})
                if (
                    state.get("stopped")
                    or getattr(engine, "stop_reason", lambda: "")()
                    or (wire_gate and getattr(wire_gate, "stop_reason", lambda: "")())
                ):
                    break
        finally:
            context.close()
            browser.close()

    seen_xhr = set()
    xhr = []
    for item in captured:
        key = (item.get("method"), item.get("url"), item.get("identity"), item.get("page"))
        if key in seen_xhr:
            continue
        seen_xhr.add(key)
        xhr.append(item)

    stop_reason = (
        state.get("reason")
        or getattr(engine, "stop_reason", lambda: "")()
        or (getattr(wire_gate, "stop_reason", lambda: "")() if wire_gate else "")
    )
    payload: dict[str, Any] = {
        "ok": bool(pages) and not bool(stop_reason),
        "url": start,
        "pages": pages,
        "forms": forms,
        "links": list(dict.fromkeys(links)),
        "hash_routes": list(dict.fromkeys(hash_routes)),
        "js_files": list(dict.fromkeys(js_files)),
        "xhr": xhr,
        "api_requests": xhr,
        "errors": errors,
        **frontier.snapshot(),
        **auth.summary(),
    }
    if stop_reason:
        payload["stop_reason"] = str(stop_reason)
        payload["error"] = "crawl stopped: " + str(stop_reason)
    elif not pages:
        payload["error"] = "crawl did not complete a scoped page"
    host = urlparse(start).hostname or ""
    payload["records"] = parse_browser_crawl({**payload, "asset_texts": asset_texts}, target=host, base=start)
    return payload
