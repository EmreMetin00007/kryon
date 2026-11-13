"""Playwright BFS crawl + XHR capture → surface-shaped JSON (optional dep)."""

from __future__ import annotations

import asyncio
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse, urlsplit, urlunsplit

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
    """Run Playwright Sync API off FastMCP's asyncio loop.

    sync_playwright() raises if a loop is already running:
    'It looks like you are using Playwright Sync API inside the asyncio loop.'
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pw-sync") as pool:
        return pool.submit(fn).result(timeout=timeout)


def _is_enqueueable(url: str) -> bool:
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in SKIP_EXT):
        return False
    if path.endswith(".js"):
        return False
    return True


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

    scripts_dir = str(Path(__file__).resolve().parents[3] / "scripts")
    browser_dir = str(Path(__file__).resolve().parents[2] / "mcp-browser")
    for directory in (scripts_dir, browser_dir):
        if directory not in sys.path:
            sys.path.insert(0, directory)
    try:
        from policy_engine import PolicyEngine, ScopeResolver
        from cco_browser_core.policy import install_readonly_request_gate
        scope = ScopeResolver()
        if not scope.permits_url(start) or not _origin(start):
            raise ValueError("crawl start URL is outside active scope")
        if wire_gate is not None and not callable(wire_gate):
            raise ValueError("crawl request gate is unavailable")
        engine = _GateAdapter(wire_gate) if wire_gate else PolicyEngine()
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        return {"ok": False, "error": f"crawl policy unavailable: {type(exc).__name__}",
                "url": start, "records": [], "pages": [], "xhr": []}

    extra_headers = _parse_header_blob(headers)
    if session_target or identity:
        from . import session_store
        # Resolve in the trusted tool process. Never send vault material in
        # model arguments, summaries, or the crawler's public output.
        if (not session_target or not identity or cookie or extra_headers
                or not scope.permits_url(session_target)
                or _origin(session_target) != _origin(start)):
            return {"ok": False, "error": "crawl session binding mismatch"}
        session = session_store.verified_session(session_target, identity)
        if session is None:
            return {"ok": False, "error": "crawl session unavailable or not recently verified"}
        extra_headers = dict(session.get("headers") or {})
        if session.get("cookies"):
            extra_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in session["cookies"].items())
        engine = _SessionGateAdapter(engine, session_target, identity, session)
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


def _origin(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        return (parsed.scheme, parsed.hostname.lower(), port) if port > 0 else None
    except ValueError:
        return None


class _GateAdapter:
    def __init__(self, gate):
        self.gate = gate
        self.accounts_campaign_requests = getattr(gate, "accounts_campaign_requests", False)

    def validate_wire_invocation(self, tool_name, args):
        allowed, reason = self.gate(args["method"], args["url"], args.get("headers") or {})
        return {"allowed": bool(allowed), "reason": str(reason or "blocked")}


class _SessionGateAdapter:
    """Recheck the exact checked secret version before every browser request."""

    def __init__(self, engine, target, identity, session):
        self.engine, self.target, self.identity, self.session = engine, target, identity, session
        self.accounts_campaign_requests = getattr(engine, "accounts_campaign_requests", False)
        self.stopped = ""

    def stop_reason(self):
        return self.stopped

    def validate_wire_invocation(self, tool_name, args):
        from . import session_store
        if _origin(args.get("url", "")) != _origin(self.target):
            return {"allowed": False, "reason": "crawl request outside session origin"}
        if self.stopped or not session_store.same_verified_session(self.target, self.identity, self.session):
            self.stopped = "crawl session changed or expired"
            return {"allowed": False, "reason": "crawl session changed, expired or outside origin"}
        return self.engine.validate_wire_invocation(tool_name, args)


def _crawl_site_sync(start, max_pages, extra_headers, timeout_ms, allow_subdomains, wait_ms,
                     scope, engine, tool_name, install_gate, wire_gate, identity="anonymous",
                     source_records=None, max_actions=40):
    captured = []
    pages = []
    forms = []
    links = []
    js_files = []
    errors = []
    from feature_frontier import UnifiedFrontier, metadata_url
    from crawl_auth import CrawlAuthBoundary
    from runtime_feature_crawl import explore_features
    frontier = UnifiedFrontier(start, scope.permits_url, identity)
    frontier.add(start, source="entry-point")
    frontier.add_records(source_records or [])
    auth = CrawlAuthBoundary(getattr(engine, "session", {}).get("check_url", start),
                             authenticated=identity != "anonymous")
    visited = set()
    action_budget = max(0, int(max_actions))

    origin = _origin(start)

    def permitted(url):
        return _origin(url) == origin and scope.permits_url(url)

    def _on_response(resp):
        try:
            req = resp.request
            if (req.resource_type in ("xhr", "fetch") and str(req.method).upper() in {"GET", "HEAD", "OPTIONS"}
                    and permitted(req.url)):
                item = {
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                    "identity": identity,
                    "page": metadata_url(page.url),
                    "status": resp.status,
                }
                headers_map = {}
                try:
                    headers_map = req.headers or {}
                except Exception:
                    headers_map = {}
                ctype = headers_map.get("content-type") or headers_map.get("Content-Type") or ""
                if ctype:
                    item["content_type"] = ctype
                captured.append(item)
                frontier.add(req.url, source="runtime-xhr", kind="operation", method=req.method)
            elif req.resource_type == "script":
                frontier.add(req.url, source="runtime-bundle", kind="bundle")
        except Exception:
            pass

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, args=CHROMIUM_ARGS)
        context_kwargs = {
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
            excluded = {"cookie", "host", "origin", "referer", "content-length", "connection",
                        "transfer-encoding", "proxy-authorization", "user-agent"}
            safe_headers = {str(k): str(v) for k, v in extra_headers.items() if str(k).lower() not in excluded}
            def stopped(reason):
                observer = getattr(wire_gate, "observe", None)
                if callable(observer):
                    status = {"http_401": 401, "http_429": 429, "login_redirect": 302}.get(reason)
                    if status:
                        observer(extra_headers, {"ok": True, "status": status,
                                                 "location": "/login" if reason == "login_redirect" else ""})
            state = install_gate(context, engine, tool_name,
                                 header_provider=lambda url: safe_headers if permitted(url) else {},
                                 request_filter=lambda url, headers: permitted(url), on_stop=stopped,
                                 auth_boundary=auth if isinstance(engine, _SessionGateAdapter) or identity == "anonymous" else None)
            if cookie:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(cookie)
                if not parsed_cookie:
                    raise ValueError("crawl session cookie cannot be parsed")
                parsed = urlsplit(start)
                origin_url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
                context.add_cookies([{"name": name, "value": morsel.value, "url": origin_url}
                                     for name, morsel in parsed_cookie.items()])
            page = context.new_page()
            page.on("response", _on_response)
            def ensure_active():
                from browser_session_control import check_bound_session
                check = (lambda: check_bound_session(context, engine, tool_name, engine.target,
                                                      engine.identity, engine.session)) if isinstance(engine, _SessionGateAdapter) else None
                reason = auth.resolve(check)
                if reason:
                    state.update(stopped=True, reason=reason)
                    stopped(reason)
                if state.get("stopped") or getattr(engine, "stop_reason", lambda: "")():
                    raise RuntimeError("crawl stopped")
                if not permitted(page.url):
                    raise ValueError("crawl navigated outside allowed scope")

            def collect():
                for anchor in page.query_selector_all("a[href]"):
                    href = anchor.get_attribute("href") or ""
                    if not href or href.startswith(("javascript:", "mailto:", "data:")):
                        continue
                    from urllib.parse import urljoin
                    absolute = urljoin(page.url, href)
                    frontier.add(absolute, source="runtime-link", kind="page" if _is_enqueueable(absolute) else "bundle")
                    if permitted(absolute):
                        links.append(absolute)
                for script in page.query_selector_all("script[src]"):
                    from urllib.parse import urljoin
                    absolute = urljoin(page.url, script.get_attribute("src") or "")
                    frontier.add(absolute, source="runtime-bundle", kind="bundle")
                    if permitted(absolute):
                        js_files.append(absolute)

            while frontier.pending("page") and len(visited) < max(1, int(max_pages)):
                work = frontier.take("page")
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
                    pages.append({"url": current, "status": status, "title": title[:180], "identity": identity})
                    frontier.finish(work)
                    collect()
                    capture_index = [len(captured)]
                    def feature_harvest():
                        collect()
                        new = captured[capture_index[0]:]
                        capture_index[0] = len(captured)
                        return [item["method"] + " " + metadata_url(item["url"]) for item in new]
                    action_budget -= explore_features(page, frontier, action_budget, feature_harvest,
                                                      ensure_active, wait_ms)

                    for form in page.query_selector_all("form"):
                        from urllib.parse import urljoin
                        action = urljoin(page.url, form.get_attribute("action") or page.url)
                        if not permitted(action):
                            continue
                        method = (form.get_attribute("method") or "GET").upper()
                        fields = []
                        for inp in form.query_selector_all("input, textarea, select"):
                            name = inp.get_attribute("name") or ""
                            typ = inp.get_attribute("type") or "text"
                            if name:
                                field_item = {"name": name, "type": typ}
                                fields.append(field_item)
                        forms.append({
                            "page": current,
                            "action": action,
                            "method": method,
                            "fields": fields,
                        })

                except Exception as exc:
                    errors.append({"url": current, "error": str(exc)[:160]})
                if (state.get("stopped") or getattr(engine, "stop_reason", lambda: "")()
                        or (wire_gate and getattr(wire_gate, "stop_reason", lambda: "")())):
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

    stop_reason = (state.get("reason") or getattr(engine, "stop_reason", lambda: "")()
                   or (getattr(wire_gate, "stop_reason", lambda: "")() if wire_gate else ""))
    payload = {
        "ok": bool(pages) and not bool(stop_reason),
        "url": start,
        "pages": pages,
        "forms": forms,
        "links": list(dict.fromkeys(links)),
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
    payload["records"] = parse_browser_crawl(payload, target=host, base=start)
    return payload
