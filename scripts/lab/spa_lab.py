#!/usr/bin/env python3
"""SPA biçimli kör yüzey laboratuvarı (WS2 kapsama ölçümü).

Klasik blind_lab'dan farkı: rotalar ana sayfada bağlantı olarak YOK.
Bilgi yalnız JS paketi, JS'nin andığı OpenAPI belgesi, robots ve sitemap
içinde. Keşif sürecine doğruluk listesi verilmez; puanlama operatör tarafında.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

APP_JS = """
const SPEC_URL = '/assets/spec-v9.json';
const LEGACY = '/api/v2';
fetch('/api/search?q=laptop&sort=new');
fetch('/api/notes', {method: 'POST', body: JSON.stringify({title: t, body: b})});
axios.put(`/api/orders/${orderId}`, {total: 5});
axios({url: '/api/login', method: 'post', data: {username: u, password: p}});
fetch(`/api/users/${userId}/docs?full=1`);
fetch('/graphql', {method: 'POST', body: JSON.stringify({
  query: 'query GetOrder($id: ID!, $verbose: Boolean) { order(id: $id) { total } }',
  variables: {id: oid, verbose: true}})});
"""

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "SPA Lab"},
    "paths": {
        "/api/invoices/{invoiceId}": {
            "get": {"parameters": [
                {"name": "invoiceId", "in": "path"},
                {"name": "download", "in": "query"}]},
            "delete": {"parameters": [{"name": "invoiceId", "in": "path"}]},
        },
        "/api/upload": {"post": {"requestBody": {"content": {
            "application/json": {"schema": {"properties": {
                "filename": {}, "kind": {}}}}}}}},
    },
}

# Doğruluk listesi: (metot, yol şablonu, parametre adları)
TRUTH = [
    {"method": "GET", "path": "/", "params": []},
    {"method": "GET", "path": "/about", "params": []},
    {"method": "GET", "path": "/api/search", "params": ["q", "sort"]},
    {"method": "POST", "path": "/api/notes", "params": ["title", "body"]},
    {"method": "PUT", "path": "/api/orders/{orderId}", "params": ["orderId", "total"]},
    {"method": "POST", "path": "/api/login", "params": ["username", "password"]},
    {"method": "GET", "path": "/api/users/{userId}/docs", "params": ["userId", "full"]},
    {"method": "POST", "path": "/graphql", "params": ["id", "verbose"]},
    {"method": "GET", "path": "/api/invoices/{invoiceId}",
     "params": ["invoiceId", "download"]},
    {"method": "DELETE", "path": "/api/invoices/{invoiceId}", "params": ["invoiceId"]},
    {"method": "POST", "path": "/api/upload", "params": ["filename", "kind"]},
    {"method": "GET", "path": "/internal/health", "params": []},
    {"method": "GET", "path": "/legacy/report", "params": ["year"]},
]

HOME = '<html><head><script src="/assets/app.js"></script></head>' \
       '<body><a href="/about">About</a><div id="root"></div></body></html>'


def build_truth() -> list[dict]:
    return [dict(row) for row in TRUTH]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _route(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self._send(200, HOME, "text/html")
        if path == "/assets/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/assets/spec-v9.json":
            return self._send(200, json.dumps(SPEC))
        if path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /internal/health\n",
                              "text/plain")
        if path == "/sitemap.xml":
            return self._send(
                200,
                '<?xml version="1.0"?><urlset>'
                "<url><loc>/legacy/report?year=2026</loc></url></urlset>",
                "application/xml")
        known = {row["path"].split("{")[0].rstrip("/") for row in TRUTH}
        if any(path == item or path.startswith(item + "/") for item in known if item):
            return self._send(200, json.dumps({"ok": True, "path": path}))
        return self._send(404, json.dumps({"error": "missing"}))

    do_GET = _route
    do_POST = _route
    do_PUT = _route
    do_DELETE = _route


def _path_matches(truth_path: str, record_path: str) -> bool:
    truth_parts = [part for part in truth_path.split("/") if part]
    record_parts = [part for part in record_path.split("/") if part]
    if truth_path == "/" or record_path == "/":
        return truth_path == record_path
    if len(truth_parts) != len(record_parts):
        return False
    for expected, actual in zip(truth_parts, record_parts):
        if expected.startswith("{") and expected.endswith("}"):
            continue
        if actual.startswith("{") and actual.endswith("}"):
            continue
        if expected != actual:
            return False
    return True


def score_surface(truth: list[dict], rows: list[dict]) -> dict:
    """Kapsama puanı: rota (metot+yol) ve parametre oranları + fazla rotalar."""
    found, missed, param_found, param_total = [], [], 0, 0
    matched_rows = set()
    for expected in truth:
        hit_index, hit_params = None, set()
        for index, row in enumerate(rows):
            record_path = str(row.get("path") or urlsplit(str(
                row.get("url") or "")).path)
            if str(row.get("method") or "GET").upper() != expected["method"]:
                continue
            if not _path_matches(expected["path"], record_path):
                continue
            hit_index = index
            hit_params = {str(p.get("name")) for p in row.get("params") or []
                          if isinstance(p, dict)}
            break
        if hit_index is None:
            missed.append(f"{expected['method']} {expected['path']}")
            param_total += len(expected["params"])
            continue
        matched_rows.add(hit_index)
        found.append(f"{expected['method']} {expected['path']}")
        param_found += len(set(expected["params"]) & hit_params)
        param_total += len(expected["params"])
    extras = []
    for index, row in enumerate(rows):
        record_path = str(row.get("path") or urlsplit(str(row.get("url") or "")).path)
        if index in matched_rows:
            continue
        if record_path.startswith("/api/") or record_path == "/graphql":
            if not any(_path_matches(item["path"], record_path) for item in truth):
                extras.append(f"{row.get('method') or 'GET'} {record_path}")
    routes_total = len(truth)
    return {
        "routes_found": len(found), "routes_total": routes_total,
        "route_coverage": round(len(found) / routes_total, 3) if routes_total else 0,
        "params_found": param_found, "params_total": param_total,
        "param_coverage": round(param_found / param_total, 3) if param_total else 0,
        "missed": missed, "extra_routes": sorted(set(extras)),
    }


def serve(port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    server.daemon_threads = True
    return server
