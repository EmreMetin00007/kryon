#!/usr/bin/env python3
"""
CCO Vuln Lab — kasıtlı zafiyetli, LOOPBACK-ONLY test hedefi (yetkili).
=====================================================================
SADECE 127.0.0.1'e bağlanır; gerçek bir hedefe DOKUNMAZ. `auto_fanout_variants(live=True)`
ve erişim-kontrolü zincirini güvenle doğrulamak için tasarlanmış bilinçli-zafiyetli uygulama.

Zafiyetler (eğitim amaçlı):
  • GET /search?q=        → yansıyan XSS (q escape edilmeden basılır)
  • GET /search?sort=     → formda gizli; JS/OpenAPI'den keşfedilir
  • GET /portal → /portal/secret?token=  → derinlik-2 (discover tek hop kaçırır)
  • GET /item?id=         → hata-tabanlı SQLi
  • POST /login           → auth form + hidden csrf; Cookie session
  • GET /account          → cookie yoksa 401
  • GET/POST /api/notes   → JSON API; debug query + title yansıması
  • GET /openapi.json     → OpenAPI 3 spec
  • GET /app.js           → gizli path/param (sort, debug, /api/notes)
  • GET /api/orders/<id>  → BOLA
  • GET /admin/export     → BFLA/unauth
  • GET /checkout?price=&quantity= → iş mantığı
  • GET /go?next=         → open redirect
  • GET /waf/item?id=     → SQLi behind keyword WAF (/**/ / %0a bypass)
  • GET /waf/search?q=    → XSS behind <script WAF

 Yardimci endpoint:
  • GET /healthz          → docker healthcheck için 200/ok

Kullanım:  python3 vuln_lab.py [port]     (port 0 → rastgele)
"""
import sys
import json
import html
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, parse_qsl, urlparse

# sahte veri — order'lar farklı kullanıcılara ait (BOLA kanıtı için sahip işaretçileri)
ORDERS = {
    "1001": {"owner": "userA", "email": "alice@lab.local", "total": 250, "item": "Laptop"},
    "1002": {"owner": "userB", "email": "bob@lab.local", "total": 99, "item": "Mouse"},
    "1003": {"owner": "userC", "email": "carol@lab.local", "total": 12, "item": "Cable"},
}


def _auth_identity(headers):
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return ""


def _sql_waf_blocks(value: str) -> bool:
    """Block canonical SQLi; allow comment/whitespace/case-split mutations."""
    raw = value or ""
    if "/**/" in raw or "%0a" in raw or "%09" in raw or "%0d" in raw:
        return False
    if "'" in raw or '"' in raw:
        return True
    if re.search(r"\b(AND|OR|UNION|SELECT)\b", raw, re.I):
        return True
    return False


class LabHandler(BaseHTTPRequestHandler):
    server_version = "VulnLab/1.0"

    def _send(self, code, body, ctype="text/html", extra_headers=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        path = u.path

        if path == "/healthz":
            self._send(200, "ok", "text/plain")
            return

        if path == "/app.js":
            self._send(200, (
                "const API='/api/notes';\n"
                "fetch('/api/notes?debug=1',{method:'POST',headers:{'Content-Type':'application/json'},"
                "body:JSON.stringify({title:'x',body:'y'})});\n"
                "window.SEARCH='/search?q=test&sort=new';\n"
            ), "application/javascript")
            return

        if path == "/openapi.json":
            host = self.headers.get("Host") or "127.0.0.1"
            origin = f"http://{host}"
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "VulnLab", "version": "1.0"},
                "servers": [{"url": origin}],
                "paths": {
                    "/search": {"get": {"parameters": [
                        {"name": "q", "in": "query"}, {"name": "sort", "in": "query"},
                    ]}},
                    "/item": {"get": {"parameters": [{"name": "id", "in": "query"}]}},
                    "/login": {"post": {"requestBody": {"content": {
                        "application/x-www-form-urlencoded": {"schema": {"properties": {
                            "username": {}, "password": {}, "csrf": {},
                        }}}
                    }}}},
                    "/api/notes": {"post": {"requestBody": {"content": {
                        "application/json": {"schema": {"properties": {"title": {}, "body": {}}}}
                    }}}},
                },
            }
            self._send(200, json.dumps(spec), "application/json")
            return

        if path == "/login":
            self._send(200, """<html><body>
<h1>Login</h1>
<form action="/login" method="POST">
  <input type="hidden" name="csrf" value="labcsrf">
  <input name="username" value="userA">
  <input name="password" type="password" value="userA">
  <button type="submit">giriş</button>
</form>
</body></html>""")
            return

        if path == "/account":
            cookie = self.headers.get("Cookie") or ""
            if "session=" not in cookie:
                self._send(401, "<html>login required</html>")
                return
            self._send(200, f"<html><body>account ok {html.escape(cookie)}</body></html>")
            return

        if path == "/api/notes":
            debug = (q.get("debug") or [""])[0]
            payload = {"notes": [{"id": 1, "title": "hello", "owner": "userA"}]}
            if debug:
                payload["debug"] = {"query": "SELECT * FROM notes", "param": debug}
            self._send(200, json.dumps(payload), "application/json")
            return

        # --- 1) Yansıyan XSS ---
        if path == "/search":
            term = (q.get("q") or [""])[0]
            sort = (q.get("sort") or [""])[0]
            # ZAFİYET: escape YOK (q ve gizli sort)
            self._send(200, f"<html><body><h1>Arama</h1><p>Sonuç: {term}</p><p>sort={sort}</p></body></html>")
            return

        if path == "/safe/search":
            term = html.escape((q.get("q") or [""])[0])
            self._send(200, f"<html><body><h1>Arama</h1><p>Sonuç: {term}</p></body></html>")
            return

        # --- 2b) WAF-önü SQLi / XSS (canonical payload 403, mutasyon geçer) ---
        if path == "/waf/item":
            iid = (q.get("id") or [""])[0]
            if _sql_waf_blocks(iid):
                self._send(
                    403,
                    "This error was generated by Mod_Security",
                    "text/html",
                    {"Server": "Mod_Security"},
                )
                return
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO items (id, name) VALUES (1, 'Widget')")
            try:
                row = conn.execute(f"SELECT id, name FROM items WHERE id = {iid}").fetchone()
            except sqlite3.Error:
                self._send(500, "<b>Database error:</b> You have an error in your SQL syntax; "
                                "check the manual near '%s'" % html.escape(iid))
                return
            finally:
                conn.close()
            if row:
                self._send(200, f"<html><body>Ürün #{row[0]}: {html.escape(row[1])}</body></html>")
            else:
                self._send(200, "<html><body>Ürün bulunamadı</body></html>")
            return

        if path == "/waf/search":
            term = (q.get("q") or [""])[0]
            if re.search(r"<script", term, re.I):
                self._send(
                    403,
                    "This error was generated by Mod_Security",
                    "text/html",
                    {"Server": "Mod_Security"},
                )
                return
            self._send(200, f"<html><body><h1>Arama</h1><p>Sonuç: {term}</p></body></html>")
            return

        # --- 2) Boolean + hata-tabanlı SQLi ---
        if path == "/item":
            iid = (q.get("id") or [""])[0]
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO items (id, name) VALUES (1, 'Widget')")
            try:
                row = conn.execute(f"SELECT id, name FROM items WHERE id = {iid}").fetchone()
            except sqlite3.Error:
                # ZAFİYET: ham SQL hatası sızdırır
                self._send(500, "<b>Database error:</b> You have an error in your SQL syntax; "
                                "check the manual near '%s'" % html.escape(iid))
                return
            finally:
                conn.close()
            if row:
                self._send(200, f"<html><body>Ürün #{row[0]}: {html.escape(row[1])}</body></html>")
            else:
                self._send(200, "<html><body>Ürün bulunamadı</body></html>")
            return

        if path == "/safe/item":
            iid = (q.get("id") or [""])[0]
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO items (id, name) VALUES (1, 'Widget')")
            row = conn.execute("SELECT id, name FROM items WHERE id = ?", (iid,)).fetchone()
            conn.close()
            if row:
                self._send(200, f"<html><body>Ürün #{row[0]}: {html.escape(row[1])}</body></html>")
            else:
                self._send(200, "<html><body>Ürün bulunamadı</body></html>")
            return

        # --- 3) BOLA (object-level authz yok) ---
        if path.startswith("/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            order = ORDERS.get(oid)
            if not order:
                self._send(404, json.dumps({"error": "not found"}), "application/json")
                return
            # ZAFİYET: Authorization header'ı doğrulanmıyor → herkes her order'ı görür
            self._send(200, json.dumps(order), "application/json")
            return

        if path.startswith("/safe/api/orders/"):
            oid = path.rsplit("/", 1)[-1]
            order = ORDERS.get(oid)
            if not order:
                self._send(404, json.dumps({"error": "not found"}), "application/json")
                return
            if _auth_identity(self.headers) != order["owner"]:
                self._send(403, json.dumps({"error": "forbidden"}), "application/json")
                return
            self._send(200, json.dumps(order), "application/json")
            return

        # --- 4) BFLA / unauth admin ---
        if path == "/admin/export":
            # ZAFİYET: token kontrolü yok → herkes tüm veriyi export eder
            self._send(200, json.dumps({"export": list(ORDERS.values()),
                                        "classification": "all-customer-pii"}), "application/json")
            return

        if path == "/safe/admin/export":
            if _auth_identity(self.headers) != "admin":
                self._send(403, json.dumps({"error": "forbidden"}), "application/json")
                return
            self._send(200, json.dumps({"export": list(ORDERS.values()),
                                        "classification": "all-customer-pii"}), "application/json")
            return

        # --- 5) İş mantığı: negatif fiyat/miktar ---
        if path == "/checkout":
            try:
                price = float((q.get("price") or ["0"])[0])
                qty = int((q.get("quantity") or ["1"])[0])
            except ValueError:
                self._send(400, json.dumps({"error": "bad params"}), "application/json")
                return
            total = price * qty  # ZAFİYET: negatif/sıfır doğrulaması yok
            self._send(200, json.dumps({"price": price, "quantity": qty, "total": total,
                                        "charged": total}), "application/json")
            return

        # --- 6) Open redirect ---
        if path == "/go":
            dest = (q.get("next") or q.get("url") or ["/"])[0] or "/"
            self._send(302, "redirect", "text/plain", {"Location": dest})
            return

        if path == "/safe/go":
            dest = (q.get("next") or q.get("url") or ["/"])[0] or "/"
            # Browsers normalize backslashes before resolving a redirect.
            parsed = urlparse(dest.replace("\\", "/"))
            if parsed.scheme or parsed.netloc:
                self._send(302, "redirect", "text/plain", {"Location": "/"})
                return
            self._send(302, "redirect", "text/plain", {"Location": dest})
            return

        if path == "/home":
            self._send(200, "<html><body>Lab home</body></html>")
            return

        if path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /api/\n", "text/plain")
            return

        if path == "/sitemap.xml":
            host = self.headers.get("Host") or "127.0.0.1"
            origin = f"http://{host}"
            body = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
                f"<sitemap><loc>{origin}/sitemap-pages.xml</loc></sitemap>"
                "</sitemapindex>"
            )
            self._send(200, body, "application/xml")
            return

        if path == "/sitemap-pages.xml":
            host = self.headers.get("Host") or "127.0.0.1"
            origin = f"http://{host}"
            body = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">"
                f"<url><loc>{origin}/search?q=test</loc></url>"
                f"<url><loc>{origin}/item?id=1</loc></url>"
                f"<url><loc>{origin}/checkout?price=10&amp;quantity=1</loc></url>"
                f"<url><loc>{origin}/go?next=/home</loc></url>"
                "</urlset>"
            )
            self._send(200, body, "application/xml")
            return

        if path == "/portal":
            self._send(200, """<html><body>
<h1>Portal</h1>
<a href="/portal/secret?token=labtoken">secret</a>
</body></html>""")
            return

        if path == "/portal/secret":
            token = (q.get("token") or [""])[0]
            self._send(200, f"<html><body>secret ok token={html.escape(token)}</body></html>")
            return

        if path == "/":
            self._send(200, """<html><head><title>VulnLab</title>
<script src="/app.js"></script></head><body>
<h1>VulnLab</h1>
<form action="/search" method="GET"><input name="q" value="test"></form>
<form action="/checkout" method="GET">
  <input name="price" value="10"><input name="quantity" value="1">
</form>
<a href="/search?q=test">search</a>
<a href="/item?id=1">item</a>
<a href="/login">login</a>
<a href="/portal">portal</a>
<a href="/account">account</a>
<a href="/api/orders/1001">order</a>
<a href="/admin/export">admin export</a>
<a href="/checkout?price=10&quantity=1">checkout</a>
<a href="/go?next=/home">go</a>
<a href="/openapi.json">openapi</a>
<a href="/healthz">health</a>
</body></html>""")
            return
        self._send(404, "<html>404</html>")

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()

        if path == "/login":
            form = dict(parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))
            user = form.get("username") or ""
            if not user:
                self._send(401, "<html>bad login</html>")
                return
            self._send(302, "ok", "text/plain", {
                "Location": "/account",
                "Set-Cookie": f"session={user}; Path=/",
            })
            return

        if path == "/api/notes":
            data = {}
            if "json" in ctype:
                try:
                    data = json.loads(raw.decode("utf-8", "replace") or "{}")
                except json.JSONDecodeError:
                    data = {}
            else:
                data = dict(parse_qsl(raw.decode("utf-8", "replace"), keep_blank_values=True))
            title = str(data.get("title") or "")
            body = str(data.get("body") or "")
            self._send(200, json.dumps({"ok": True, "title": title, "body": body}), "application/json")
            return

        self._send(404, "<html>404</html>")

    def log_message(self, *a):
        pass


def serve(port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    return srv


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = serve(port)
    print(f"VulnLab → http://127.0.0.1:{srv.server_address[1]}  (Ctrl-C ile durdur)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()
