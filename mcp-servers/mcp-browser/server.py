#!/usr/bin/env python3
"""MCP Browser Server — Playwright tabanlı web tarayıcı + ekran görüntüsü.

HackerAgent'ın görsel (vision) yeteneği için: web sayfasını render edip
screenshot alır, OCR için metin çıkarır, form alanlarını keşfeder.

Tools:
  • browser_screenshot(url, full_page=True) → base64 PNG + metadata
  • browser_extract_text(url) → görünen metin
  • browser_get_forms(url) → form alanları, input'lar, CSRF token'ları

Playwright gereksinimi — opsiyonel dependency:
    pip install playwright
    playwright install chromium

Playwright olmadan link çıkarma, politika denetimli düz HTTP kullanabilir.
"""

from __future__ import annotations

import base64
import os
import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from mcp.server.fastmcp import FastMCP

try:
    from playwright.sync_api import sync_playwright  # type: ignore
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

_OWN_DIR = os.path.dirname(os.path.abspath(__file__))
if _OWN_DIR not in sys.path:
    sys.path.insert(0, _OWN_DIR)
_SURFACE_DIR = os.path.abspath(os.path.join(_OWN_DIR, "..", "mcp-memory-server"))
if _SURFACE_DIR not in sys.path:
    sys.path.insert(0, _SURFACE_DIR)
try:
    from cco_surface_core.parsers import parse_browser_crawl, parse_xhr
    from cco_surface_core.store import ingest_records, memory_db_path, write_artifact
    from cco_surface_core.crawl import run_playwright_sync as _run_playwright_sync
    HAS_SURFACE = True
except Exception:
    HAS_SURFACE = False
    parse_browser_crawl = parse_xhr = ingest_records = memory_db_path = write_artifact = None
    _run_playwright_sync = None

try:
    from cco_browser_core.hooks import build_runtime_hook_script, normalize_runtime_events
    HAS_RUNTIME_HOOKS = True
except Exception:
    HAS_RUNTIME_HOOKS = False
    build_runtime_hook_script = normalize_runtime_events = None

try:
    from cco_browser_core.fallback import extract_links_plain
    HAS_FALLBACK = True
except Exception:
    HAS_FALLBACK = False
    extract_links_plain = None

try:
    from cco_browser_core.session import SESSION as _BROWSER_SESSION
    HAS_SESSION = True
except Exception:
    HAS_SESSION = False
    _BROWSER_SESSION = None

CCO_HOME = os.environ.get("CCO_HOME", os.path.expanduser("~/.cco"))
SCREENSHOT_DIR = os.path.join(CCO_HOME, "screenshots")
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

mcp = FastMCP(
    "browser",
    instructions=(
        "Playwright tabanlı web tarayıcı — screenshot, DOM analizi, form keşfi. "
        "Vision-capable LLM'ler bu screenshot'ı base64 image olarak yorumlayabilir."
    ),
)

DEFAULT_VIEWPORT = {"width": 1366, "height": 800}
DEFAULT_TIMEOUT = 30_000  # 30s
MAX_IMAGE_B64_CHARS = 4_000_000  # ~3MB base64 (LLM limit'lerini aşma)
CHROMIUM_ARGS = ["--no-sandbox", "--disable-dev-shm-usage"]

# Mitm proxy: trafik scope-traffic.jsonl'a loglansin diye browser da
# proxy'den gecer. CCO_PROXY="" ise proxy kapali. Proxy ayakta degilse
# otomatik direkt baglanti (tarama durmaz).
CCO_PROXY = os.environ.get("CCO_PROXY", "http://127.0.0.1:8080").strip()
# Hepsiburada WAF headless-shell'i yakalayip 403 veriyor; headed (X :0.0) 200.
# CCO_HEADED=1 ise headed acilir.
CCO_HEADED = os.environ.get("CCO_HEADED", "0").strip().lower() in {"1", "true", "yes"}


def _proxy_available() -> bool:
    if not CCO_PROXY:
        return False
    try:
        import socket as _s
        u = urlparse(CCO_PROXY)
        host, port = u.hostname or "127.0.0.1", u.port or 8080
        with _s.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def _research_headers() -> dict:
    handle = os.environ.get("HACKERONE_HANDLE", "").strip()
    if not handle:
        return {}
    name = os.environ.get("CCO_RESEARCH_HEADER", "X-HackerOne-Research").strip()
    return {name: handle} if name else {}


def _new_context(browser, tool_name: str):
    """Disposable browser context with a gate on every read-only request."""
    scripts_dir = os.path.abspath(os.path.join(_OWN_DIR, "..", "..", "scripts"))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from policy_engine import PolicyEngine
    from cco_browser_core.policy import install_readonly_request_gate
    engine = PolicyEngine()
    kwargs = {"viewport": DEFAULT_VIEWPORT, "ignore_https_errors": True,
              "service_workers": "block"}
    if _proxy_available():
        kwargs["proxy"] = {"server": CCO_PROXY}
    rh = _research_headers()
    if rh:
        kwargs["extra_http_headers"] = rh
    context = browser.new_context(**kwargs)
    try:
        install_readonly_request_gate(context, engine, tool_name)
    except Exception:
        context.close()
        raise
    return context


def _target_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in (url or "") else f"http://{url or ''}")
    return parsed.hostname or (url or "")


_SCOPE_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def _scope_allowlist():
    """Load the same URL-prefix and exclusion rules as the central gate."""
    repo_root = os.path.abspath(os.path.join(_OWN_DIR, "..", ".."))
    try:
        scripts_dir = os.path.join(repo_root, "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from policy_engine import ScopeResolver
        return ScopeResolver(repo_root=repo_root)
    except (ImportError, OSError, RuntimeError, ValueError):
        return None


def _host_in_scope(url: str, allow) -> bool:
    return bool(allow and allow.permits_url(url))


def _ingest_browser(records, url: str, prefix: str):
    if not HAS_SURFACE or not records:
        return None, ""
    if os.environ.get("CCO_SURFACE_AUTO_INGEST", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None, ""
    target = _target_from_url(url)
    try:
        ingest = ingest_records(records, target=target, db_path=memory_db_path())
        artifact = write_artifact({"target": target, "ingest": ingest, "count": len(records)}, prefix=prefix)
        return ingest, artifact
    except Exception as exc:
        return {"error": str(exc)}, ""


def _missing_playwright_msg() -> str:
    return (
        "HATA: playwright kurulu değil. Kurulum:\n"
        "  pip install playwright\n"
        "  playwright install chromium\n"
    )


def _playwright_sync(fn, timeout: float = 180):
    """Playwright Sync API cannot run inside FastMCP's asyncio loop."""
    if _run_playwright_sync is not None:
        return _run_playwright_sync(fn, timeout=timeout)
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pw-sync") as pool:
        return pool.submit(fn).result(timeout=timeout)


@mcp.tool()
def browser_screenshot(
    url: str,
    full_page: bool = True,
    wait_seconds: float = 2.0,
    return_base64: bool = True,
) -> str:
    """Bir URL'nin ekran görüntüsünü alır.

    Vision-capable LLM'ler için base64-encoded PNG döndürür. Agent bu
    sonucu `{"type": "image_url", "image_url": {"url": "data:image/png;base64,<b64>"}}`
    biçimine dönüştürerek multimodal LLM'e gönderebilir.

    Args:
        url: Ziyaret edilecek URL (http/https)
        full_page: Tüm sayfayı mı yoksa sadece viewport'u mu yakala
        wait_seconds: Sayfa yüklendikten sonra render için bekleme süresi
        return_base64: True → JSON'da base64 dön, False → sadece dosya yolu

    Returns: JSON-like string — path, base64 (opsiyonel), boyutlar, title
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    ts = int(__import__("time").time())
    safe = re.sub(r"[^a-z0-9]+", "_", url.lower())[:80]
    path = os.path.join(SCREENSHOT_DIR, f"{ts}_{safe}.png")

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_screenshot")
                page = ctx.new_page()
                page.set_default_timeout(DEFAULT_TIMEOUT)
                page.goto(url, wait_until="domcontentloaded")
                page.wait_for_timeout(int(wait_seconds * 1000))
                title = page.title()
                page.screenshot(path=path, full_page=full_page)
                ctx.close()
                browser.close()
                return title
        title = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Screenshot alınamadı: {e}"

    size = os.path.getsize(path)
    out = {
        "url": url,
        "title": title[:200],
        "path": path,
        "size_bytes": size,
        "full_page": full_page,
    }
    if return_base64:
        with open(path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        if len(b64) > MAX_IMAGE_B64_CHARS:
            out["base64"] = None
            out["base64_skipped_reason"] = f"size>{MAX_IMAGE_B64_CHARS}"
        else:
            out["base64"] = b64
            out["data_url"] = f"data:image/png;base64,{b64}"
    import json as _json
    return _json.dumps(out, ensure_ascii=False)


@mcp.tool()
def browser_extract_text(url: str, wait_seconds: float = 2.0) -> str:
    """Bir URL'den görünen text içeriğini çıkarır (JS render sonrası).

    Args:
        url: URL (http/https)
        wait_seconds: Sayfa yüklendikten sonra bekleme

    Returns: Temizlenmiş düz metin (max 15000 karakter)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_extract_text")
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                text = page.evaluate("() => document.body.innerText")
                ctx.close()
                browser.close()
                return text
        text = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Metin çıkarılamadı: {e}"

    text = (text or "").strip()
    if len(text) > 15_000:
        text = text[:15_000] + "\n…[kırpıldı]"
    return text or "(boş sayfa)"


@mcp.tool()
def browser_get_forms(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfadaki form, input ve token adlarını değerlerini saklamadan keşfeder.

    Web exploit vektörleri için ilk adım (SQLi, XSS, CSRF analizi).

    Args:
        url: URL
        wait_seconds: Render bekleme

    Returns: JSON — form listesi (action, method, inputs, tokens)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    script = """
    () => {
        const forms = Array.from(document.querySelectorAll('form')).map(f => {
            const inputs = Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                name: i.name || i.id || '',
                type: i.type || i.tagName.toLowerCase(),
                value_sample: i.value ? '<redacted>' : '',
                required: i.required,
                placeholder: i.placeholder || '',
            }));
            return {
                action: f.action || '',
                method: (f.method || 'get').toUpperCase(),
                id: f.id || '',
                inputs: inputs,
            };
        });
        const metaTokens = Array.from(document.querySelectorAll('meta[name*="token" i], meta[name*="csrf" i]'))
            .map(m => ({ name: m.name, present: Boolean(m.content) }));
        return { forms, meta_tokens: metaTokens, url: location.href };
    }
    """

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_get_forms")
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                data = page.evaluate(script)
                ctx.close()
                browser.close()
                return data
        data = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Form analizi başarısız: {e}"

    import json as _json
    return _json.dumps(data, ensure_ascii=False, indent=2)


def _extract_links_fallback(url: str) -> dict:
    """GET with session and policy checks on every redirect, then parse HTML."""
    base = {"fallback": "plain-http", "fallback_source": "plain-http-get",
            "limitations": ["JavaScript is not executed", "XHR traffic is not captured"]}
    if not HAS_FALLBACK:
        return {**base, "error": "fallback_parser_unavailable"}
    try:
        validator_dir = os.path.abspath(os.path.join(_OWN_DIR, "..", "mcp-validator"))
        scripts_dir = os.path.abspath(os.path.join(_OWN_DIR, "..", "..", "scripts"))
        for path in (validator_dir, scripts_dir):
            if path not in sys.path:
                sys.path.insert(0, path)
        from cco_validator_core.egress import egress_request, scoped_wire_gate
        from policy_engine import PolicyEngine
        import requests

        engine = PolicyEngine()

        def gate(method, request_url, headers):
            result = engine.validate_wire_invocation("browser_browser_extract_links", {
                "target": request_url, "url": request_url, "method": method, "headers": headers})
            return result["allowed"], result["reason"]

        def send(method, request_url, *, params, data, headers, timeout):
            proxies = {"http": CCO_PROXY, "https": CCO_PROXY} if _proxy_available() else None
            return requests.request(method, request_url, params=params, data=data, headers=headers,
                                    timeout=timeout, allow_redirects=False, verify=False, proxies=proxies)

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0",
                   **_research_headers()}
        with scoped_wire_gate(gate):
            response = egress_request("GET", url, headers=headers, timeout=15, transport=send,
                                      use_shared_session=True, stop_on_login_redirect=True)
        status = response.get("status")
        meta = {**base, "status": status, "requests_sent": response.get("requests_sent", 0)}
        if not response.get("ok") or response.get("blocked"):
            return {**meta, "error": "request_blocked" if response.get("blocked") else "request_failed",
                    "blocked": response.get("blocked", "transport")}
        if not isinstance(status, int) or not 200 <= status < 300:
            return {**meta, "error": "http_status"}
        data = extract_links_plain(response.get("text") or "", response.get("final_url") or url)
        return {**data, **meta}
    except Exception as exc:
        return {**base, "error": "fallback_unavailable", "error_type": type(exc).__name__}


@mcp.tool()
def browser_extract_links(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfadaki tüm linkleri, script kaynaklarını ve form action'larını çıkarır.

    Saldırı yüzeyi haritalaması için ilk adım — internal/external link ayrımı,
    JS dosyaları (secret/endpoint analizi için), parametreli URL'ler.

    Args:
        url: URL (http/https)
        wait_seconds: JS render bekleme
    """
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    if not HAS_PLAYWRIGHT:
        import json as _json
        data = _extract_links_fallback(url)
        data["fallback_reason"] = "playwright_unavailable"
        if data.get("error"):
            return _json.dumps(data, ensure_ascii=False, indent=2)
    else:
        data = None

    script = """
    () => {
        const origin = location.origin;
        const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
        const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
        const forms = Array.from(document.querySelectorAll('form')).map(f => f.action || location.href);
        const internal = [], external = [];
        [...new Set(links)].forEach(h => {
            try { (new URL(h).origin === origin ? internal : external).push(h); } catch(e) {}
        });
        const withParams = [...new Set(links)].filter(h => h.includes('?') && h.includes('='));
        return {
            internal_links: internal.slice(0, 300),
            external_links: external.slice(0, 200),
            js_files: [...new Set(scripts)].slice(0, 100),
            form_actions: [...new Set(forms)],
            urls_with_params: withParams.slice(0, 150),
        };
    }
    """
    if data is None:
        try:
            def _work():
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                    ctx = _new_context(browser, "browser_browser_extract_links")
                    page = ctx.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                    page.wait_for_timeout(int(wait_seconds * 1000))
                    data = page.evaluate(script)
                    ctx.close()
                    browser.close()
                    return data
            data = _playwright_sync(_work)
        except Exception:
            data = _extract_links_fallback(url)
            data["fallback_reason"] = "playwright_error"
            if data.get("error"):
                import json as _json
                return _json.dumps(data, ensure_ascii=False, indent=2)

    import json as _json
    data["url"] = url
    if HAS_SURFACE:
        records = parse_browser_crawl(data, target=_target_from_url(url), base=url)
        ingest, artifact = _ingest_browser(records, url, "browser-links")
        if ingest:
            data["surface_ingest"] = ingest
            if artifact:
                data["surface_artifact"] = artifact
    return _json.dumps(data, ensure_ascii=False, indent=2)


@mcp.tool()
def browser_security_headers(url: str) -> str:
    """HTTP yanıt güvenlik başlıklarını analiz eder ve eksik olanları raporlar.

    CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy kontrolü — clickjacking, MIME sniffing, downgrade riskleri.

    Args:
        url: URL (http/https)
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    important = {
        "content-security-policy": "XSS/injection azaltma (CSP)",
        "strict-transport-security": "HTTPS downgrade koruması (HSTS)",
        "x-frame-options": "Clickjacking koruması",
        "x-content-type-options": "MIME sniffing koruması",
        "referrer-policy": "Referrer bilgi sızıntısı koruması",
        "permissions-policy": "Tarayıcı özellik kısıtlama",
    }
    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_security_headers")
                page = ctx.new_page()
                resp = page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                headers = {k.lower(): v for k, v in (resp.headers if resp else {}).items()}
                status = resp.status if resp else None
                ctx.close()
                browser.close()
                return headers, status
        headers, status = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Header analizi başarısız: {e}"

    present, missing = {}, []
    for h, desc in important.items():
        if h in headers:
            present[h] = headers[h][:300]
        else:
            missing.append({"header": h, "risk": desc})

    leaky = {h: headers[h] for h in ("server", "x-powered-by", "x-aspnet-version") if h in headers}

    import json as _json
    return _json.dumps(
        {
            "url": url,
            "status": status,
            "present_security_headers": present,
            "missing_security_headers": missing,
            "information_disclosure": leaky,
            "severity": "medium" if missing else "info",
        },
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_cookie_audit(url: str, wait_seconds: float = 2.0) -> str:
    """Sayfanın set ettiği cookie'lerin güvenlik flag'lerini denetler.

    HttpOnly, Secure, SameSite eksikliği → session hijacking / CSRF riski.

    Args:
        url: URL (http/https)
        wait_seconds: Render bekleme
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_cookie_audit")
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                cookies = ctx.cookies()
                ctx.close()
                browser.close()
                return cookies
        cookies = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Cookie denetimi başarısız: {e}"

    audited = []
    for c in cookies:
        issues = []
        if not c.get("httpOnly"):
            issues.append("HttpOnly eksik (XSS ile çalınabilir)")
        if not c.get("secure"):
            issues.append("Secure eksik (HTTP üzerinden sızabilir)")
        if not c.get("sameSite") or c.get("sameSite") == "None":
            issues.append("SameSite zayıf/eksik (CSRF riski)")
        audited.append({
            "name": c.get("name"),
            "domain": c.get("domain"),
            "httpOnly": c.get("httpOnly"),
            "secure": c.get("secure"),
            "sameSite": c.get("sameSite"),
            "issues": issues,
        })

    import json as _json
    return _json.dumps(
        {"url": url, "cookie_count": len(audited), "cookies": audited},
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_capture_requests(url: str, wait_seconds: float = 4.0) -> str:
    """Sayfa yüklenirken yapılan tüm XHR/fetch/API isteklerini yakalar.

    SPA'larda gizli API endpoint keşfi için kritik — JS'in arka planda
    konuştuğu backend route'larını ortaya çıkarır.

    Args:
        url: URL (http/https)
        wait_seconds: İstekleri toplamak için bekleme süresi
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    captured = []

    def _on_request(req):
        try:
            if req.resource_type in ("xhr", "fetch", "websocket", "document"):
                captured.append({
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                })
        except Exception:
            pass

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_capture_requests")
                page = ctx.new_page()
                page.on("request", _on_request)
                page.goto(url, wait_until="networkidle", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                ctx.close()
                browser.close()
                return list(captured)
        captured[:] = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: İstek yakalama başarısız: {e} (yakalanan: {len(captured)})"

    # Dedup
    seen, unique = set(), []
    for c in captured:
        key = (c["method"], c["url"])
        if key not in seen:
            seen.add(key)
            unique.append(c)

    import json as _json
    payload = {"url": url, "api_requests": unique, "total": len(unique), "xhr": unique}
    if HAS_SURFACE:
        records = parse_xhr(payload, target=_target_from_url(url), base=url)
        ingest, artifact = _ingest_browser(records, url, "browser-xhr")
        if ingest:
            payload["surface_ingest"] = ingest
            if artifact:
                payload["surface_artifact"] = artifact
    return _json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
def browser_runtime_observe(url: str, wait_seconds: float = 3.0, max_events: int = 200) -> str:
    """Sayfayı salt-gözlem runtime kancalarıyla yükler ve API davranışını toplar.

    fetch, XMLHttpRequest ve WebSocket çağrılarının yalnızca method, URL,
    header/alan adları, durum ve süre metadatası alınır. Storage/cookie
    değerleri, istek gövdeleri ve yanıt gövdeleri okunmaz.

    Args:
        url: URL (http/https)
        wait_seconds: Sayfa yüklendikten sonra gözlem süresi
        max_events: Toplanacak azami runtime olayı
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not HAS_RUNTIME_HOOKS:
        return "HATA: browser runtime hook çekirdeği yüklenemedi"
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_runtime_observe")
                ctx.add_init_script(build_runtime_hook_script(max_events=max_events))
                page = ctx.new_page()
                page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(max(0.0, wait_seconds) * 1000))
                data = page.evaluate(
                    """() => ({
                        events: (window.__ccoRuntime && window.__ccoRuntime.events) || [],
                        state: (window.__ccoRuntime && window.__ccoRuntime.snapshot)
                            ? window.__ccoRuntime.snapshot() : {}
                    })"""
                )
                ctx.close()
                browser.close()
                return data
        data = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Runtime gözlemi başarısız: {e}"

    payload = normalize_runtime_events(data.get("events") or [], data.get("state") or {})
    payload["url"] = url
    if HAS_SURFACE:
        records = parse_xhr(
            {"api_requests": payload["requests"]},
            target=_target_from_url(url),
            base=url,
        )
        ingest, artifact = _ingest_browser(records, url, "browser-runtime")
        if ingest:
            payload["surface_ingest"] = ingest
            if artifact:
                payload["surface_artifact"] = artifact
    import json as _json
    return _json.dumps(payload, ensure_ascii=False, indent=2)


@mcp.tool()
def browser_console_logs(url: str, wait_seconds: float = 3.0) -> str:
    """Sayfanın JavaScript console mesajlarını ve hatalarını yakalar.

    Console error/warning'ler bilgi sızıntısı (stack trace, API key, debug log)
    ve DOM XSS ipuçları içerebilir.

    Args:
        url: URL (http/https)
        wait_seconds: Mesaj toplama süresi
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    logs, errors = [], []

    def _on_console(msg):
        try:
            logs.append({"type": msg.type, "text": msg.text[:500]})
        except Exception:
            pass

    def _on_pageerror(exc):
        errors.append(str(exc)[:500])

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_console_logs")
                page = ctx.new_page()
                page.on("console", _on_console)
                page.on("pageerror", _on_pageerror)
                page.goto(url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                ctx.close()
                browser.close()
        _playwright_sync(_work)
    except Exception as e:
        return f"HATA: Console yakalama başarısız: {e}"

    import json as _json
    return _json.dumps(
        {
            "url": url,
            "console_messages": logs[:100],
            "page_errors": errors[:50],
            "error_count": len([m for m in logs if m["type"] == "error"]) + len(errors),
        },
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_dom_xss_probe(url: str, param: str = "q", wait_seconds: float = 2.0) -> str:
    """DOM-based XSS için reflection probe — benzersiz canary enjekte eder.

    Belirtilen query parametresine eşsiz bir işaretçi + zararsız XSS payload'u
    enjekte eder; payload'un DOM'a yansıyıp yansımadığını ve alert()/dialog
    tetiklenip tetiklenmediğini gözlemler. (Doğrulama amaçlı, non-destructive.)

    Args:
        url: Hedef URL (http/https)
        param: Test edilecek query parametresi adı
        wait_seconds: Render bekleme
    """
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not url.startswith(("http://", "https://")):
        return "HATA: URL http:// veya https:// ile başlamalı"

    import time as _t
    canary = f"cco{int(_t.time())}xss"
    payload = f'{canary}"><img src=x onerror=window.__ccoXss=1>'

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))

    dialog_fired = {"v": False}

    def _on_dialog(d):
        dialog_fired["v"] = True
        try:
            d.dismiss()
        except Exception:
            pass

    try:
        def _work():
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=not CCO_HEADED, args=CHROMIUM_ARGS)
                ctx = _new_context(browser, "browser_browser_dom_xss_probe")
                page = ctx.new_page()
                page.on("dialog", _on_dialog)
                page.goto(test_url, wait_until="domcontentloaded", timeout=DEFAULT_TIMEOUT)
                page.wait_for_timeout(int(wait_seconds * 1000))
                html = page.content()
                xss_marker = page.evaluate("() => window.__ccoXss === 1")
                ctx.close()
                browser.close()
                return html, xss_marker
        html, xss_marker = _playwright_sync(_work)
    except Exception as e:
        return f"HATA: XSS probe başarısız: {e}"

    reflected_raw = canary in html and '"><img' in html
    reflected_any = canary in html
    verdict = "LIKELY VULNERABLE" if (xss_marker or dialog_fired["v"] or reflected_raw) else \
              ("REFLECTED (escaped?)" if reflected_any else "no reflection")

    import json as _json
    return _json.dumps(
        {
            "tested_url": test_url,
            "param": param,
            "canary": canary,
            "reflected": reflected_any,
            "reflected_unescaped": reflected_raw,
            "js_executed": bool(xss_marker),
            "dialog_triggered": dialog_fired["v"],
            "verdict": verdict,
            "severity": "high" if (xss_marker or reflected_raw) else "info",
        },
        ensure_ascii=False, indent=2,
    )


# ============================================================
# OTURUMLU ETKİLEŞİM (Plan 1-3: CDP attach + click/fill + kimlikli crawl)
# ============================================================

def _session_guard():
    if not HAS_PLAYWRIGHT:
        return _missing_playwright_msg()
    if not HAS_SESSION:
        return "HATA: oturum çekirdeği yüklenemedi (cco_browser_core.session)"
    return ""


def _session_call(fn, tool_name, current_url=None):
    import json as _json
    guard = _session_guard()
    if guard:
        return guard
    try:
        def invoke(session):
            action = fn if current_url is None else lambda current: current._authorize_current(tool_name, current_url, fn)
            return session._invoke(tool_name, action)
        return _json.dumps(_BROWSER_SESSION.call(invoke),
                           ensure_ascii=False, indent=2)
    except TimeoutError as exc:
        return f"HATA: {exc}"
    except Exception as exc:  # noqa: BLE001
        return f"HATA: oturum işlemi: {exc}"


@mcp.tool()
def browser_session_open(url: str = "", cdp_url: str = "") -> str:
    """Kalıcı tarayıcı oturumu açar (etkileşim aletleri bundan sonra çalışır).

    CDP yalnız yerel loopback adresine bağlanır ve mevcut sekmelere dokunmadan
    ayrı, politika denetimli bir context açar. Önceden sağlanan test oturumu
    paylaşılan session store'dan aynı origin için yüklenir. Yazma metotları
    ve WebSocket bu context'te kapalıdır.

    Args:
        url: Açılışta gidilecek kapsam içi URL (zorunlu)
        cdp_url: Chrome DevTools adresi (ör. http://127.0.0.1:9222)
    """
    if not url.startswith(("http://", "https://")):
        return "HATA: geçerli kapsam içi başlangıç URL'si gerekli"
    cdp = cdp_url or os.environ.get("CCO_BROWSER_CDP", "").strip()
    return _session_call(lambda s: s._open(url=url, cdp_url=cdp, headed=CCO_HEADED),
                         "browser_browser_session_open")


@mcp.tool()
def browser_session_goto(url: str) -> str:
    """Oturumdaki sayfayı adrese götürür (yalnız http/https)."""
    if not (url.startswith("http://") or url.startswith("https://")):
        return "HATA: yalnızca http/https adresleri"
    return _session_call(lambda s: s._goto(url), "browser_browser_session_goto")


@mcp.tool()
def browser_session_snapshot(url: str = "") -> str:
    """Aktif sayfanın URL'sini vererek etkileşimli öğeleri listeler."""
    return _session_call(lambda s: s._snapshot(), "browser_browser_session_snapshot", url)


@mcp.tool()
def browser_session_click(target: str, url: str = "") -> str:
    """Aktif URL üzerinde seçili öğeye tıklar; yalnız salt-okunur ağ istekleri geçer."""
    return _session_call(lambda s: s._click(target), "browser_browser_session_click", url)


@mcp.tool()
def browser_session_fill(selector: str, value: str, url: str = "") -> str:
    """Aktif URL üzerindeki bir alanı doldurur; ağ yazma istekleri engellenir."""
    return _session_call(lambda s: s._fill(selector, value), "browser_browser_session_fill", url)


@mcp.tool()
def browser_session_press(key: str = "Enter", url: str = "") -> str:
    """Aktif URL üzerinde klavye tuşu gönderir."""
    return _session_call(lambda s: s._press(key), "browser_browser_session_press", url)


@mcp.tool()
def browser_session_text(url: str = "") -> str:
    """Doğrulanan aktif URL'nin başlık ve görünür metin özetini verir."""
    return _session_call(lambda s: s._text(), "browser_browser_session_text", url)


@mcp.tool()
def browser_session_crawl(max_pages: int = 20, url: str = "") -> str:
    """Aktif oturumla aynı-origin sayfaları gezer; bulunan yüzey hafızaya işlenir.

    Login sonrası (kimlikli) crawl buradan yapılır: önce session_open +
    (insan veya fill ile) login, sonra crawl. Sayfalar memory'ye endpoint
    olarak kaydedilir, hunter döngüsü oradan beslenir.
    """
    import json as _json
    guard = _session_guard()
    if guard:
        return guard
    try:
        result = _BROWSER_SESSION.call(lambda s: s._invoke(
            "browser_browser_session_crawl", lambda current: current._authorize_current(
                "browser_browser_session_crawl", url, lambda authorized: authorized._crawl(max_pages=max_pages))))
    except Exception as exc:  # noqa: BLE001
        return f"HATA: crawl: {exc}"
    ingest = None
    if HAS_SURFACE and result.get("pages"):
        records = parse_browser_crawl(
            {"url": result["start"], "pages": result["pages"]},
            target=_target_from_url(result["start"]))
        ingest, _artifact = _ingest_browser(records, result["start"], "browser-crawl")
    return _json.dumps({"crawl": result, "ingested": ingest},
                       ensure_ascii=False, indent=2)


@mcp.tool()
def browser_session_requests(clear: bool = False, url: str = "") -> str:
    """Oturum başından beri biriken XHR/fetch isteklerini döndürür ve hafızaya işler.

    Yalnız yanıt alınmış salt-okunur isteklerin metadatası envantere girer.
    Gövdeler ve sorgu değerleri tutulmaz; eksik bağlam yürütülebilir sayılmaz.

    Args:
        clear: True ise döndürdükten sonra birikimi sıfırlar
    """
    import json as _json
    guard = _session_guard()
    if guard:
        return guard
    try:
        result = _BROWSER_SESSION.call(lambda s: s._invoke(
            "browser_browser_session_requests", lambda current: current._authorize_current(
                "browser_browser_session_requests", url, lambda authorized: authorized._collected_requests(clear=clear))))
    except Exception as exc:  # noqa: BLE001
        return f"HATA: istek toplama: {exc}"
    ingest = None
    manifests: list[dict] = []
    scope_filtered_out = 0
    scoped: list[dict] = []
    if result.get("requests"):
        allow = _scope_allowlist()
        scoped = [r for r in result["requests"]
                  if _host_in_scope(str(r.get("url") or ""), allow)]
        scope_filtered_out = len(result["requests"]) - len(scoped)
        if scoped:
            first_url = scoped[0]["url"]
            if HAS_SURFACE:
                records = parse_xhr({"api_requests": scoped},
                                    target=_target_from_url(first_url))
                ingest, _artifact = _ingest_browser(records, first_url, "browser-session-requests")
            try:
                scripts_dir = os.path.abspath(os.path.join(_OWN_DIR, "..", "..", "scripts"))
                if scripts_dir not in sys.path:
                    sys.path.insert(0, scripts_dir)
                from workflow_compiler import compile_workflow_manifests
                manifests = compile_workflow_manifests(
                    scoped,
                    target_ref=_target_from_url(first_url) or "target",
                    # All input URLs have already passed the central resolver.
                    allow=None,
                )
            except Exception:
                manifests = []
    # Do not return entries that were rejected by the same scope filter used
    # for ingestion. This is a post-capture filter, not a wire-level gate.
    result = {**result, "requests": scoped}
    return _json.dumps(
        {"collected": result, "ingested": ingest, "workflow_manifests": manifests,
         "scope_filtered_out": scope_filtered_out},
        ensure_ascii=False, indent=2,
    )


@mcp.tool()
def browser_session_close() -> str:
    """Oturumu kapatır. CDP modunda yalnız bağlantı kesilir; kullanıcı Chrome'u açık kalır."""
    return _session_call(lambda s: s._close(), "browser_browser_session_close")


if __name__ == "__main__":
    mcp.run()
