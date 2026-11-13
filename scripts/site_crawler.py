#!/usr/bin/env python3
"""Genel site crawler (keşif amaçlı, non-destructive).

Ne yapar:
  - Aynı-host linkleri gezer (max sayfa sınırlı, hız sınırlı)
  - XHR/fetch API isteklerini yakalar -> route envanteri
  - Konsol hatalarını toplar (stack trace / leak ipucu)
  - Trafik mitmproxy'den geçerse ham log da düşer

Ne yapmaz:
  - Form göndermez, tıklama ile state değiştirmez
  - Mutating istekleri (POST/PUT/DELETE) tekrarlamaz, sadece kaydeder

Kullanım:
  python3 scripts/site_crawler.py --url https://dashboard.rapyd.net/ \\
      --init-js 'localStorage.setItem("token","...");localStorage.setItem("fp","...")' \\
      --seeds seeds.txt --max-pages 40 --delay 2

Çıktılar: /root/.cco/crawl-<host>/  (repo dışı, secret bulaşmaz)
"""
import argparse
import json
import os
import secrets
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import tech_routes

CCO = Path(os.environ.get("CCO_HOME", "/root/.cco")).expanduser()
PROXY = "http://127.0.0.1:8080"
FUZZ_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """301/302'yi takip etme: hem kesif sinyali korunur hem scope-disina cikilmaz."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _url_opener(use_proxy: bool):
    handlers = [_NoRedirect()]
    if use_proxy:
        proxy = os.environ.get("CCO_PROXY", PROXY).strip()
        if proxy:
            try:
                u = urlparse(proxy)
                with socket.create_connection((u.hostname or "127.0.0.1",
                                               u.port or 8080), timeout=2.0):
                    pass
                handlers.append(urllib.request.ProxyHandler(
                    {"http": proxy, "https": proxy}))
            except OSError:
                print("[crawl] proxy erisilemiyor, direkt devam", flush=True)
    return urllib.request.build_opener(*handlers)


def _research_headers() -> dict:
    handle = os.environ.get("HACKERONE_HANDLE", "").strip()
    if not handle:
        return {}
    name = os.environ.get("CCO_RESEARCH_HEADER", "X-HackerOne-Research").strip()
    return {name: handle} if name else {}


def discover_routes(base_url: str, delay: float, use_proxy: bool) -> dict:
    """Link-disi rota kesfi: teknoloji-bilincli mini liste (butceli).

    Dondurur: {route_key: {"count", "statuses", "source"}} (routes.json ile uyumlu).
    """
    opener = _url_opener(use_proxy)
    base = base_url.rstrip("/")

    def get(path: str):
        req = urllib.request.Request(
            base + path, headers={"User-Agent": FUZZ_UA, **_research_headers()})
        try:
            with opener.open(req, timeout=10) as r:
                return r.status, r.headers, r.read(20000)
        except urllib.error.HTTPError as e:
            try:
                body = e.read(20000)
            except Exception:
                body = b""
            return e.code, e.headers or {}, body
        except Exception as e:  # noqa: BLE001
            return None, {}, str(e)[:100].encode()

    st, hdr, body = get("/")
    get_hdr = lambda k: hdr.get(k, "") if hasattr(hdr, "get") else ""  # noqa: E731
    words, techs = tech_routes.build_wordlist(
        server=get_hdr("Server"), powered_by=get_hdr("X-Powered-By"),
        body=body.decode("utf-8", "replace") if isinstance(body, bytes) else "")
    print(f"[crawl] route-fuzz: {len(words)} rota, teknoloji: {techs or ['bilinmiyor']}",
          flush=True)

    cst, _, cbody = get(f"/cco-calib-{secrets.token_hex(4)}")
    soft_404_size = len(cbody) if cst == 200 else None

    found: dict = {}
    for w in words:
        path = "/" + w
        rst, _, rbody = get(path)
        time.sleep(delay)
        if rst is None:
            continue
        if rst == 404:
            continue
        if soft_404_size is not None and rst == 200 and len(rbody) == soft_404_size:
            continue
        if rst not in (200, 201, 204, 301, 302, 307, 308, 401, 403):
            continue
        key = f"GET {path}"
        found[key] = {"count": 1, "statuses": {str(rst): 1}, "source": "route-fuzz"}
        print(f"[crawl] fuzz-buldu: {rst} {path}", flush=True)
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--init-js", default="")
    ap.add_argument("--seeds", default="")
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--headed", action="store_true",
                    help="Headless yakalaniyorsa (WAF 403) headed ac (X :0.0)")
    ap.add_argument("--no-discover-routes", action="store_true",
                    help="Link-disi mini route kesfini kapat (varsayilan: acik)")
    ap.add_argument("--route-delay", type=float, default=1.0,
                    help="Route kesfi istek arasi bekleme sn (scope rps'e gore ayarla)")
    a = ap.parse_args()

    from playwright.sync_api import sync_playwright

    host = urlparse(a.url).netloc
    outdir = CCO / f"crawl-{host}"
    outdir.mkdir(exist_ok=True)
    pages_log = (outdir / "pages.jsonl").open("a")
    api_log = (outdir / "api-requests.jsonl").open("a")
    console_log = (outdir / "console-errors.jsonl").open("a")
    routes: dict = {}
    if (outdir / "routes.json").exists():
        routes = json.loads((outdir / "routes.json").read_text())

    queue = [a.url]
    if a.seeds:
        queue += [l.strip() for l in Path(a.seeds).read_text().splitlines()
                  if l.strip() and not l.startswith("#")]
    seen: set[str] = set()

    with sync_playwright() as pw:
        kwargs = {"ignore_https_errors": True}
        if not a.no_proxy:
            kwargs["proxy"] = {"server": PROXY}
        rh = _research_headers()
        if rh:
            kwargs["extra_http_headers"] = rh
        browser = pw.chromium.launch(headless=not a.headed, args=["--no-sandbox"])
        ctx = browser.new_context(**kwargs)
        if a.init_js:
            ctx.add_init_script(a.init_js)
        page = ctx.new_page()
        page.on("console",
                lambda m: console_log.write(json.dumps(
                    {"type": m.type, "text": m.text[:500]}) + "\n")
                if m.type == "error" else None)

        collected_api: list[dict] = []

        def on_req(req) -> None:  # noqa: ANN001
            if req.resource_type not in ("xhr", "fetch"):
                return
            u = urlparse(req.url)
            if u.netloc != host:
                return
            key = f"{req.method} {u.path}"
            e = routes.get(key, {"count": 0})
            e["count"] += 1
            if u.query:
                e["sample_query"] = u.query[:300]
            post_body = ""
            try:
                post_body = (req.post_data or "")[:1000]
            except Exception:
                post_body = ""
            if post_body:
                e["has_post_body"] = True
            routes[key] = e
            rec = {"method": req.method, "url": req.url[:500]}
            if post_body:
                rec["post_body"] = post_body
            collected_api.append(rec)
            api_log.write(json.dumps(rec) + "\n")

        page.on("request", on_req)

        count = 0
        while queue and count < a.max_pages:
            url = queue.pop(0)
            if url in seen or urlparse(url).netloc != host:
                continue
            seen.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=30000)
                page.wait_for_timeout(1500)
                title = page.title()
                links = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
                for ln in links:
                    if urlparse(ln).netloc == host and ln not in seen:
                        queue.append(ln)
                pages_log.write(json.dumps(
                    {"url": url, "title": title[:120],
                     "new_links": len(links)}) + "\n")
                count += 1
                print(f"[crawl] {count}/{a.max_pages} {url[:80]} ({title[:40]})",
                      flush=True)
            except Exception as e:  # noqa: BLE001
                pages_log.write(json.dumps({"url": url, "error": str(e)[:200]})
                                + "\n")
                print(f"[crawl] HATA {url[:80]} :: {str(e)[:100]}", flush=True)
            time.sleep(a.delay)
        browser.close()

    if not a.no_discover_routes:
        for k, e in discover_routes(a.url, a.route_delay, not a.no_proxy).items():
            routes.setdefault(k, e)

    (outdir / "routes.json").write_text(json.dumps(routes, indent=1,
                                                   sort_keys=True))
    try:
        mem_dir = Path(__file__).resolve().parent.parent / "mcp-servers" / "mcp-memory-server"
        if str(mem_dir) not in sys.path:
            sys.path.insert(0, str(mem_dir))
        from cco_surface_core.parsers import parse_xhr
        from cco_surface_core.store import ingest_records
        base_origin = f"{urlparse(a.url).scheme}://{host}"
        for rk in routes:
            parts = rk.split(" ", 1)
            if len(parts) == 2:
                collected_api.append({"method": parts[0], "url": base_origin + parts[1]})
        records = parse_xhr({"api_requests": collected_api}, target=host, base=base_origin)
        if records:
            ingest_records(records, target=host, db_path=str(CCO / "agent_memory.db"))
    except Exception:
        pass
    print(f"[crawl] bitti: {count} sayfa, {len(routes)} API route -> {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
