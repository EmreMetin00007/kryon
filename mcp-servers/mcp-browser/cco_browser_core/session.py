"""Oturumlu tarayıcı çekirdeği: tek kalıcı Playwright thread'i.

Stateless aletler her çağrıda tarayıcıyı açıp kapatır; etkileşim (tıkla/doldur)
aynı sayfanın çağrılar arasında yaşaması ister. Bu sınıf tüm Playwright
işini tek dedike thread'de koşar (Sync API thread'e bağlıdır), çağrılar
kuyrukla serileştirilir.

Bağlantı modları:
- kendi Chromium (headless/headed)
- CDP attach: yalnız yerel Chrome'a bağlanır ve ayrı, yalıtılmış context açar.
  Mevcut kullanıcı sekmeleri ve oturumları devralınmaz; kapatma Chrome'u kapatmaz.
"""
from __future__ import annotations

import queue
import threading
import ipaddress
import os
import sys
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cco_browser_core.policy import install_readonly_request_gate

_CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]


class BrowserSession:
    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._thread: threading.Thread | None = None
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._cdp = False
        self._requests: list[dict] = []
        self._req_index: dict[int, dict] = {}
        self._hooked_pages: set[int] = set()
        self._hooked_contexts: set[int] = set()
        self._wire_tool = None
        self._session_origin = None
        self._session_headers: dict[str, str] = {}
        self._session_had_auth = False
        self._policy_state = None

    # -- thread yönetimi -------------------------------------------------
    def _ensure_thread(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(
                target=self._loop, name="cco-browser-session", daemon=True)
            self._thread.start()

    def _loop(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return
            fn, done, box = item
            try:
                box["value"] = fn(self)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc
            done.set()

    def call(self, fn, timeout: float = 120):
        self._ensure_thread()
        done = threading.Event()
        box: dict = {}
        self._q.put((fn, done, box))
        if not done.wait(timeout):
            raise TimeoutError("tarayıcı işlemi zaman aşımı")
        if "error" in box:
            raise box["error"]
        return box.get("value")

    # -- thread içinde çalışan işlemler ----------------------------------
    def _invoke(self, tool_name, fn):
        if self._wire_tool is not None:
            raise RuntimeError("nested browser invocation is not allowed")
        self._wire_tool = str(tool_name or "")
        try:
            return fn(self)
        finally:
            self._wire_tool = None

    @staticmethod
    def _origin(url: str):
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None:
                return None
            port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
            return (parsed.scheme, parsed.hostname.lower(), port) if port > 0 else None
        except ValueError:
            return None

    @staticmethod
    def _local_cdp(url: str) -> bool:
        try:
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https", "ws", "wss"} or parsed.username is not None or not parsed.hostname:
                return False
            _ = parsed.port
            host = parsed.hostname.lower()
            return host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def _headers_for_request(self, url: str) -> dict:
        return dict(self._session_headers) if self._origin(url) == self._session_origin else {}

    def _request_in_session_origin(self, url: str, _headers: dict) -> bool:
        return self._session_origin is not None and self._origin(url) == self._session_origin

    def _ensure_active(self):
        if self._policy_state and self._policy_state.get("stopped"):
            raise RuntimeError("browser session stopped: " + str(self._policy_state.get("reason") or "policy"))

    def _on_gate_stop(self, reason: str) -> None:
        if reason not in {"http_401", "login_redirect"} or not self._session_had_auth or not self._session_origin:
            return
        from cco_validator_core.egress import save_shared_session
        save_shared_session(self._session_origin[1], state="expired", source="browser_session")

    def _authorize_current(self, tool_name: str, expected_url: str, fn):
        self._require_page()
        self._ensure_active()
        scripts_dir = str(Path(__file__).resolve().parents[3] / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from target_identity import resource_identity
        from policy_engine import PolicyEngine
        current_url = str(self._page.url or "")
        if not expected_url or not resource_identity(expected_url) or resource_identity(expected_url) != resource_identity(current_url):
            raise ValueError("current browser URL is required and must match the active page")
        headers = dict(self._session_headers)
        handle = os.environ.get("HACKERONE_HANDLE", "").strip()
        name = os.environ.get("CCO_RESEARCH_HEADER", "X-HackerOne-Research").strip()
        if handle and name:
            headers[name] = handle
        result = PolicyEngine().validate_tool_invocation(tool_name, {
            "url": current_url, "method": "GET", "headers": headers})
        if not result.get("allowed"):
            raise RuntimeError("browser action policy denied: " + str(result.get("reason") or "blocked"))
        return fn(self)

    def _restore_shared_session(self, url: str, scope) -> str:
        if not url:
            return "none"
        origin = self._origin(url)
        if not origin or not scope.permits_url(url):
            raise ValueError("browser session URL is outside the active scope")
        validator_dir = str(Path(__file__).resolve().parents[2] / "mcp-validator")
        if validator_dir not in sys.path:
            sys.path.insert(0, validator_dir)
        from cco_validator_core.egress import load_shared_session
        shared = load_shared_session(url, require_origin=True)
        self._session_origin = origin
        self._session_headers = {}
        self._session_had_auth = False
        if not shared:
            return "none"
        if shared.get("state") != "active" or shared.get("stale"):
            raise RuntimeError("shared test session is expired or stale; refresh it before navigation")
        excluded = {"cookie", "host", "origin", "referer", "content-length", "connection",
                    "transfer-encoding", "proxy-authorization", "user-agent"}
        self._session_headers = {str(k): str(v) for k, v in (shared.get("headers") or {}).items()
                                 if str(k).lower() not in excluded}
        cookie = str(shared.get("cookie") or "")
        self._session_had_auth = bool(cookie or any(
            any(part in str(key).lower() for part in ("auth", "token", "session", "api-key", "api_key"))
            for key in self._session_headers))
        if cookie:
            parsed_cookie = SimpleCookie()
            parsed_cookie.load(cookie)
            if not parsed_cookie:
                raise ValueError("shared session cookie cannot be parsed")
            parsed_url = urlsplit(url)
            origin_url = urlunsplit((parsed_url.scheme, parsed_url.netloc, "/", "", ""))
            self._context.add_cookies([{"name": name, "value": morsel.value, "url": origin_url}
                                       for name, morsel in parsed_cookie.items()])
        return "restored"

    def _open(self, url: str = "", cdp_url: str = "", headed: bool = False):
        from playwright.sync_api import sync_playwright
        scripts_dir = str(Path(__file__).resolve().parents[3] / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from policy_engine import PolicyEngine, ScopeResolver
        if not self._wire_tool:
            raise RuntimeError("browser request policy context is missing")
        if cdp_url and not self._local_cdp(cdp_url):
            raise ValueError("CDP endpoint must be an explicitly local loopback URL")
        scope = ScopeResolver()
        if url and not scope.permits_url(url):
            raise ValueError("browser session URL is outside the active scope")
        if url and self._session_origin is not None and self._origin(url) != self._session_origin:
            raise ValueError("open a separate session for another origin")
        engine = PolicyEngine()
        if self._pw is None:
            self._pw = sync_playwright().start()
        if self._browser is None:
            self._cdp = bool(cdp_url)
            if cdp_url:
                self._browser = self._pw.chromium.connect_over_cdp(cdp_url)
            else:
                self._browser = self._pw.chromium.launch(
                    headless=not headed, args=_CHROMIUM_ARGS)
        if self._context is None:
            ctx_kwargs: dict = {"viewport": {"width": 1366, "height": 800},
                                "ignore_https_errors": True, "service_workers": "block"}
            proxy = self._proxy_if_available()
            if proxy:
                ctx_kwargs["proxy"] = {"server": proxy}
            handle = os.environ.get("HACKERONE_HANDLE", "").strip()
            header_name = os.environ.get("CCO_RESEARCH_HEADER", "X-HackerOne-Research").strip()
            if handle and header_name:
                ctx_kwargs["extra_http_headers"] = {header_name: handle}
            # Even when attached over CDP, do not take over a user's existing
            # context. A new context permits service workers to be blocked.
            self._context = self._browser.new_context(**ctx_kwargs)
            try:
                self._policy_state = install_readonly_request_gate(
                    self._context, engine, lambda: self._wire_tool,
                    header_provider=self._headers_for_request,
                    request_filter=self._request_in_session_origin,
                    on_stop=self._on_gate_stop)
            except Exception:
                self._context.close()
                self._context = None
                raise
        session_state = self._restore_shared_session(url, scope) if url else "none"
        if self._page is None or self._page.is_closed():
            pages = self._context.pages
            self._page = pages[0] if pages else self._context.new_page()
        self._hook_context(self._context)
        self._hook_requests(self._page)
        if url:
            self._page.goto(url, wait_until="domcontentloaded")
            self._ensure_active()
            self._sync_shared_jar()
        return {"url": self._page.url, "title": self._page.title(),
                "mode": "cdp-isolated" if self._cdp else "launched", "session_state": session_state}

    def _sync_shared_jar(self) -> None:
        """Aktif tarayıcı context cookie'lerini paylaşılan oturum kasalarına (session-jar + session_vault) yaz."""
        if self._context is None or self._page is None:
            return
        if self._policy_state and self._policy_state.get("stopped"):
            return
        try:
            import os
            import sys
            from urllib.parse import urlparse
            host = (urlparse(self._page.url or "").hostname or "").lower()
            if not host:
                return
            cookies = self._context.cookies([self._page.url]) if self._page.url else self._context.cookies()
            cdict = {
                str(c.get("name")): str(c.get("value"))
                for c in (cookies or [])
                if isinstance(c, dict) and c.get("name") and c.get("value") is not None
            }
            if not cdict:
                return
            cookie_str = "; ".join(f"{k}={v}" for k, v in cdict.items())
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            val_dir = os.path.join(base_dir, "mcp-validator")
            mem_dir = os.path.join(base_dir, "mcp-memory-server")
            if val_dir not in sys.path:
                sys.path.insert(0, val_dir)
            if mem_dir not in sys.path:
                sys.path.insert(0, mem_dir)
            from cco_validator_core.egress import save_shared_session
            save_shared_session(self._page.url, cookie=cookie_str, state="active", source="browser_session")
            try:
                from cco_surface_core import session_store
                session_store.put_session(
                    host,
                    "browser_session",
                    cookies=cdict,
                    check_url=self._page.url or "",
                )
            except Exception:
                pass
        except Exception:
            pass

    @staticmethod
    def _proxy_if_available() -> str:
        """CCO_PROXY (varsayılan mitm 8080) dinliyorsa döndür; yoksa boş.

        Proxy ölü ise tarayıcı doğrudan bağlanır, tarama durmaz.
        CDP modunda context kullanıcının tarayıcısına aittir; proxy orada
        tarayıcının kendi başlatma ayarından gelir.
        """
        import os
        import socket
        from urllib.parse import urlparse
        proxy = os.environ.get("CCO_PROXY", "http://127.0.0.1:8080").strip()
        if not proxy:
            return ""
        try:
            u = urlparse(proxy)
            with socket.create_connection((u.hostname or "127.0.0.1",
                                           u.port or 8080), timeout=1.0):
                return proxy
        except OSError:
            return ""

    # -- istek toplama -----------------------------------------------------
    _MAX_REQUESTS = 1000
    _MAX_BODY = 16384
    _SENSITIVE = ("token", "password", "passwd", "secret", "session",
                  "auth", "api_key", "apikey", "cookie", "credential")
    _SENSITIVE_EXACT = frozenset({"p", "pwd", "pass", "pin", "otp", "cvv"})

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        low = (key or "").strip().lower()
        return low in cls._SENSITIVE_EXACT or any(s in low for s in cls._SENSITIVE)

    @classmethod
    def _redact_obj(cls, obj):
        if isinstance(obj, dict):
            return {
                k: ("***" if cls._is_sensitive_key(str(k)) else cls._redact_obj(v))
                for k, v in obj.items()
            }
        if isinstance(obj, list):
            return [cls._redact_obj(x) for x in obj]
        return obj

    @classmethod
    def _redact_body(cls, body: str) -> str:
        """JSON veya form-urlencoded gövdede hassas alan değerlerini maskele (anahtarlar kalır)."""
        import json as _json
        from urllib.parse import parse_qsl, urlencode
        if not body:
            return ""
        stripped = body.strip()
        try:
            data = _json.loads(stripped)
            if isinstance(data, (dict, list)):
                redacted = cls._redact_obj(data)
                return _json.dumps(redacted, ensure_ascii=False)[: cls._MAX_BODY]
        except Exception:  # noqa: BLE001
            pass
        if "=" in stripped and not stripped.startswith("<") and not stripped.startswith("{"):
            try:
                pairs = parse_qsl(stripped, keep_blank_values=True)
                if pairs:
                    masked = [
                        (k, "***" if cls._is_sensitive_key(k) else v)
                        for k, v in pairs
                    ]
                    return urlencode(masked)[: cls._MAX_BODY]
            except Exception:  # noqa: BLE001
                pass
        return body[: cls._MAX_BODY]

    def _hook_context(self, context) -> None:
        """Context içindeki mevcut ve yeni açılacak tüm sekmeleri (popup/OAuth) dinle."""
        if context is None or id(context) in self._hooked_contexts:
            return
        self._hooked_contexts.add(id(context))
        try:
            for p in context.pages:
                self._hook_requests(p)
            context.on("page", self._hook_requests)
        except Exception:  # noqa: BLE001
            pass

    def _hook_requests(self, page) -> None:
        """Sayfaya bir kez istek + yanıt dinleyici bağla (oturum boyu birikir)."""
        if page is None or id(page) in self._hooked_pages:
            return
        self._hooked_pages.add(id(page))

        def _on_request(req) -> None:
            try:
                rtype = req.resource_type
                if rtype not in ("xhr", "fetch", "document") or str(req.method).upper() not in {"GET", "HEAD", "OPTIONS"}:
                    return
                if len(self._requests) + len(self._req_index) >= self._MAX_REQUESTS:
                    return
                record = {"method": req.method, "url": self._metadata_url(req.url),
                          "resource_type": rtype, "capture_redacted": True}
                self._req_index[id(req)] = record
            except Exception:  # noqa: BLE001
                pass

        def _on_response(resp) -> None:
            try:
                req = resp.request
                rec = self._req_index.pop(id(req), None)
                if rec is None:
                    return
                rec["status"] = resp.status
                headers = resp.headers or {}
                ctype = (headers.get("content-type") or "").lower()
                if ctype:
                    rec["content_type"] = ctype
                loc = headers.get("location")
                if loc:
                    rec["location"] = self._metadata_url(loc)
                self._requests.append(rec)
            except Exception:  # noqa: BLE001
                pass

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("requestfailed", lambda req: self._req_index.pop(id(req), None))

    @staticmethod
    def _metadata_url(url: str) -> str:
        from urllib.parse import parse_qsl, urlencode
        try:
            parsed = urlsplit(str(url or ""))
            pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
            query = urlencode([(name, "<redacted>") for name, _ in pairs])
            netloc = ""
            if parsed.netloc:
                host = parsed.hostname or ""
                if not host:
                    return ""
                netloc = f"[{host}]" if ":" in host else host
                if parsed.port is not None:
                    netloc += f":{parsed.port}"
            return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))
        except ValueError:
            return ""

    def _collected_requests(self, clear: bool = False):
        if self._page is not None:
            try:
                if not self._page.is_closed():
                    self._page.wait_for_timeout(50)
            except Exception:  # noqa: BLE001
                pass
        # Tekilleştir (method, url, post_data, status, resp_body) — durum değişimleri korunur
        seen: set = set()
        unique: list[dict] = []
        for rec in self._requests:
            key = (
                rec["method"],
                rec["url"],
                rec.get("post_data", ""),
                rec.get("status"),
                rec.get("resp_body", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(rec)
        total = len(self._requests)
        if clear:
            self._requests = []
            self._req_index = {}
        return {"total_captured": total, "unique": len(unique),
                "requests": unique}

    def _goto(self, url: str):
        self._require_page()
        origin = self._origin(url)
        if self._session_origin is not None and origin != self._session_origin:
            raise ValueError("open a separate session for another origin")
        if self._session_origin is None:
            scripts_dir = str(Path(__file__).resolve().parents[3] / "scripts")
            if scripts_dir not in sys.path:
                sys.path.insert(0, scripts_dir)
            from policy_engine import ScopeResolver
            self._restore_shared_session(url, ScopeResolver())
        self._page.goto(url, wait_until="domcontentloaded")
        self._ensure_active()
        self._sync_shared_jar()
        return {"url": self._page.url, "title": self._page.title()}

    def _snapshot(self, limit: int = 80):
        self._require_page()
        items = self._page.evaluate(
            """(limit) => {
              const out = [];
              const els = document.querySelectorAll(
                'a, button, input, select, textarea, [role=button]');
              for (const el of els) {
                if (out.length >= limit) break;
                const r = el.getBoundingClientRect();
                if (r.width === 0 && r.height === 0) continue;
                const tag = el.tagName.toLowerCase();
                const isField = (tag === 'input' || tag === 'select' || tag === 'textarea');
                const val = (!isField && el.value) ? el.value : '';
                out.push({
                  tag: tag,
                  type: el.getAttribute('type') || '',
                  name: el.getAttribute('name') || '',
                  id: el.id || '',
                  text: (el.innerText || val || '').trim().slice(0, 60),
                  href: el.getAttribute('href') || '',
                  placeholder: el.getAttribute('placeholder') || '',
                });
              }
              return out;
            }""", limit)
        return {"url": self._page.url, "title": self._page.title(),
                "elements": items}

    def _click(self, target: str, timeout_ms: int = 5000):
        self._require_page()
        if target.startswith("text="):
            self._page.get_by_text(target[5:], exact=False).first.click(
                timeout=timeout_ms)
        else:
            self._page.click(target, timeout=timeout_ms)
        self._page.wait_for_load_state("domcontentloaded")
        self._ensure_active()
        self._sync_shared_jar()
        return {"url": self._page.url, "title": self._page.title()}

    def _fill(self, selector: str, value: str, timeout_ms: int = 5000):
        self._require_page()
        self._page.fill(selector, value, timeout=timeout_ms)
        return {"url": self._page.url, "filled": selector}

    def _press(self, key: str):
        self._require_page()
        self._page.keyboard.press(key)
        self._page.wait_for_load_state("domcontentloaded")
        self._ensure_active()
        self._sync_shared_jar()
        return {"url": self._page.url, "title": self._page.title()}

    def _text(self, limit: int = 2000):
        self._require_page()
        body = self._page.evaluate(
            "() => (document.body ? document.body.innerText : '')")
        return {"url": self._page.url, "title": self._page.title(),
                "text": (body or "")[:limit]}

    def _crawl(self, max_pages: int = 20):
        self._require_page()
        from urllib.parse import urldefrag, urljoin, urlparse
        start = self._page.url
        origin = urlparse(start)
        seen: list[str] = []
        queue: list[str] = [start]
        visited: set[str] = set()
        while queue and len(seen) < max(1, int(max_pages)):
            url = urldefrag(queue.pop(0))[0]
            if url in visited:
                continue
            visited.add(url)
            try:
                self._page.goto(url, wait_until="domcontentloaded")
                self._ensure_active()
                links = self._page.evaluate(
                    "() => Array.from(document.querySelectorAll('a[href]'))"
                    ".map(a => a.href)")
            except Exception:  # noqa: BLE001
                self._ensure_active()
                continue
            seen.append(self._page.url)
            for link in links or []:
                p = urlparse(link)
                if (p.scheme in ("http", "https")
                        and p.netloc == origin.netloc
                        and urldefrag(link)[0] not in visited):
                    queue.append(urljoin(url, link))
        return {"start": start, "pages": seen, "count": len(seen)}

    def _close(self):
        try:
            if self._context is not None:
                self._context.close()
            if self._browser is not None and not self._cdp:
                self._browser.close()
        finally:
            self._browser = self._context = self._page = None
            self._requests = []
            self._req_index = {}
            self._hooked_pages = set()
            self._hooked_contexts = set()
            self._session_origin = None
            self._session_headers = {}
            self._session_had_auth = False
            self._policy_state = None
            if self._pw is not None:
                # CDP'de pw.stop() yalnız bağlantıyı keser; kullanıcının
                # Chrome'u açık kalır.
                self._pw.stop()
                self._pw = None
        return {"closed": True}

    def _require_page(self):
        if self._page is None:
            raise RuntimeError("önce browser_session_open çağırın")


SESSION = BrowserSession()
