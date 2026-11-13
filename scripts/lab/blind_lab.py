#!/usr/bin/env python3
"""Kör ölçüm laboratuvarı — seed'li, olumlu + olumsuz kontrollü hedef.

Ajan tarafı yalnızca başlangıç URL'si + test hesaplarını alır. Hangi ucun
zafiyetli olduğu, UUID'ler ve işaretler koşuya özgü seed'den üretilir ve
yalnız operatör tarafında (make_lab dönüşündeki truth) tutulur; uygulama
yanıtlarında sınıf/ipucu etiketi bulunmaz.
"""
from __future__ import annotations

import hashlib
import html
import json
import posixpath
import random
import re
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def _uuid(rng: random.Random) -> str:
    return str(uuid.UUID(int=rng.getrandbits(128), version=4))


LAB_VERSIONS = ("blind-lab/1", "blind-lab/2", "blind-lab/3")


def make_lab(seed: int, *, version: str = "blind-lab/1"):
    """(handler_class, state) döndürür. state.truth yalnız operatör içindir."""
    if version not in LAB_VERSIONS:
        raise ValueError("unknown blind lab version")
    rng = random.Random(seed)
    tag = hashlib.sha256(f"blind-{seed}".encode()).hexdigest()[:10]
    accounts = {
        label: {"token": f"tok-{tag}-{label}", "role": role}
        for label, role in (("member-a", "member"), ("member-b", "member"),
                            ("admin-a", "admin"))
    }
    by_token = {v["token"]: k for k, v in accounts.items()}

    def marker(owner: str, n: int) -> str:
        return f"{owner}-marker-{tag}-{n}@lab.local"

    orders = {}
    order_ids = {}
    for owner, vuln in (("member-a", True), ("member-a", False),
                        ("member-b", True), ("member-b", False)):
        oid = _uuid(rng)
        orders[oid] = {"owner": owner, "marker": marker(owner, len(orders)),
                       "total": 50 + rng.randrange(200), "vuln": vuln}
        order_ids.setdefault(owner, []).append(oid)

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE items (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO items VALUES (?, ?)",
                   [(1, "laptop"), (2, "mouse"), (3, "cable")])
    lock = threading.Lock()
    state = {"accounts": accounts, "orders": orders, "requests": 0, "lab_version": version,
             "db": db, "lock": lock}

    truth = [
        {"case": "sqli-item", "expected": "positive", "class": "sql_injection",
         "path": "/item", "owner": None, "actor": None},
        {"case": "xss-search", "expected": "positive", "class": "xss_reflected",
         "path": "/search", "owner": None, "actor": None},
        {"case": "ssti-hello", "expected": "positive", "class": "ssti",
         "path": "/hello", "owner": None, "actor": None},
        {"case": "redirect-go", "expected": "positive", "class": "open_redirect",
         "path": "/go", "owner": None, "actor": None},
        {"case": "traversal-file", "expected": "positive", "class": "path_traversal",
         "path": "/file", "owner": None, "actor": None},
        {"case": "bola-order", "expected": "positive", "class": "bola",
         "path": f"/orders/{order_ids['member-a'][0]}",
         "owner": "member-a", "actor": "member-b"},
        {"case": "bfla-export", "expected": "positive", "class": "bfla",
         "path": "/admin/export", "owner": "admin-a", "actor": "member-a"},
        {"case": "authbypass-statement", "expected": "positive",
         "class": "authentication_bypass", "path": "/account/statement",
         "owner": "member-a", "actor": None},
        {"case": "ctrl-sqli", "expected": "negative", "class": "sql_injection",
         "path": "/safe/item", "owner": None, "actor": None},
        {"case": "ctrl-xss", "expected": "negative", "class": "xss_reflected",
         "path": "/safe/search", "owner": None, "actor": None},
        {"case": "ctrl-ssti", "expected": "negative", "class": "ssti",
         "path": "/safe/hello", "owner": None, "actor": None},
        {"case": "ctrl-redirect", "expected": "negative", "class": "open_redirect",
         "path": "/safe/go", "owner": None, "actor": None},
        {"case": "ctrl-traversal", "expected": "negative", "class": "path_traversal",
         "path": "/safe/file", "owner": None, "actor": None},
        {"case": "ctrl-bola", "expected": "negative", "class": "bola",
         "path": f"/orders/{order_ids['member-a'][1]}",
         "owner": "member-a", "actor": "member-b"},
        {"case": "ctrl-bfla", "expected": "negative", "class": "bfla",
         "path": "/admin/users", "owner": "admin-a", "actor": "member-a"},
        {"case": "ctrl-auth", "expected": "negative",
         "class": "authentication_bypass", "path": "/account/settings",
         "owner": "member-a", "actor": None},
    ]
    state["truth"] = truth
    state["export_marker"] = marker("export", 1)
    state["statement_marker"] = marker("statement", 1)
    docs: dict = {}
    doc_seq = [0]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="text/html", extra=None):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _who(self):
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                return by_token.get(auth.split(" ", 1)[1].strip())
            return None

        def do_GET(self):
            with lock:
                state["requests"] += 1
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
            path, who = u.path, self._who()
            acct = accounts.get(who or "", {})
            if path == "/":
                links = ["/search?q=laptop", "/item?id=1", "/hello?name=guest",
                         "/go?next=/", "/file?name=notes.txt", "/notes",
                         "/admin/export", "/account/statement",
                         "/safe/search?q=laptop", "/safe/item?id=1"]
                profile = ""
                if version in {"blind-lab/2", "blind-lab/3"}:
                    links = ["/notes", *[link for link in links if link != "/notes"],
                             "/safe/hello?name=guest", "/safe/go?next=/", "/safe/file?name=notes.txt",
                             "/admin/users", "/account/settings"]
                    if who:
                        profile = '<script type="application/json">' + json.dumps(
                            {"current_user": {"id": who}}) + '</script>'
                body = "<html><title>lab shop</title>" + profile + "".join(
                    f'<a href="{h}">link</a>' for h in links) + "</html>"
                return self._send(200, body)
            if path == "/search":
                query = (f"SELECT name FROM items WHERE name LIKE "
                         f"'%{q.get('q', '')}%'")
                try:
                    with lock:
                        rows = [r[0] for r in db.execute(query)]
                    result = ",".join(rows) or "none"
                except sqlite3.Error as exc:
                    result = f"error: sqlite3.OperationalError: {exc}"
                return self._send(200, f"<html>results for {q.get('q', '')}: {result}</html>")
            if path == "/safe/search":
                with lock:
                    rows = [r[0] for r in db.execute(
                        "SELECT name FROM items WHERE name LIKE ?",
                        (f"%{q.get('q', '')}%",))]
                return self._send(200, "<html>results for "
                                  f"{html.escape(q.get('q', ''))}: {','.join(rows) or 'none'}</html>")
            if path == "/item":
                try:
                    with lock:
                        rows = [r[0] for r in db.execute(
                            f"SELECT name FROM items WHERE id = {q.get('id', '0')}")]
                    return self._send(200, f"<html>item: {','.join(rows) or 'none'}</html>")
                except sqlite3.Error as exc:
                    return self._send(200, f"<html>error: sqlite3.OperationalError: {exc}</html>")
            if path == "/safe/item":
                try:
                    iid = int(q.get("id", "0"))
                except ValueError:
                    return self._send(400, "<html>bad id</html>")
                with lock:
                    rows = [r[0] for r in db.execute(
                        "SELECT name FROM items WHERE id = ?", (iid,))]
                return self._send(200, f"<html>item: {','.join(rows) or 'none'}</html>")
            if path == "/hello":
                name = q.get("name", "")
                m = re.fullmatch(r"\{\{(\d+)\*(\d+)\}\}", name)
                if m:
                    name = str(int(m.group(1)) * int(m.group(2)))
                return self._send(200, f"<html>hello {name}</html>")
            if path == "/safe/hello":
                return self._send(200, f"<html>hello {html.escape(q.get('name', ''))}</html>")
            if path == "/go":
                return self._send(302, "", extra={"Location": q.get("next", "/")})
            if path == "/safe/go":
                nxt = q.get("next", "/")
                if (not nxt.startswith("/") or nxt.startswith("//")
                        or (version in {"blind-lab/2", "blind-lab/3"} and ("\\" in nxt or any(ord(c) < 32 for c in nxt)))):
                    return self._send(400, "<html>bad redirect</html>")
                return self._send(302, "", extra={"Location": nxt})
            if path == "/file":
                if version == "blind-lab/3":
                    # Virtual application root /public; the synthetic secret
                    # exists at /secret.txt, outside that root. No OS file I/O.
                    name = q.get("name", "")
                    virtual = {"/public/notes.txt": "lab note",
                               "/secret.txt": "root:x:0:0:synthetic:/root:/bin/bash"}
                    resolved = posixpath.normpath("/public/" + name)
                    if resolved in virtual:
                        return self._send(200, f"<html>{virtual[resolved]}</html>", "text/plain")
                    return self._send(404, "<html>no file</html>")
                files = {"notes.txt": "lab note", "secret.txt":
                         "root:x:0:0:synthetic:/root:/bin/bash"}
                name = q.get("name", "")
                key = "secret.txt" if name.endswith("secret.txt") else name
                if key in files:
                    return self._send(200, f"<html>{files[key]}</html>", "text/plain")
                return self._send(404, "<html>no file</html>")
            if path == "/safe/file":
                if ".." in q.get("name", "") or "/" in q.get("name", ""):
                    return self._send(400, "<html>bad name</html>")
                if q.get("name") == "notes.txt":
                    return self._send(200, "<html>lab note</html>", "text/plain")
                return self._send(404, "<html>no file</html>")
            if path == "/notes":
                if not who:
                    return self._send(401, "<html>login required</html>")
                mine = [{"id": oid, "href": f"/orders/{oid}",
                         "total": orders[oid]["total"],
                         "contact": orders[oid]["marker"],
                         **({"owner_id": who} if version in {"blind-lab/2", "blind-lab/3"} else {})}
                        for oid in order_ids.get(who, [])]
                return self._send(200, json.dumps({"orders": mine}),
                                  "application/json")
            if path.startswith("/orders/"):
                if not who:
                    return self._send(401, "<html>login required</html>")
                order = orders.get(path.split("/orders/", 1)[1])
                if not order:
                    return self._send(404, "<html>no order</html>")
                if not order["vuln"] and order["owner"] != who:
                    return self._send(403, "<html>forbidden</html>")
                return self._send(200, json.dumps({
                    "id": path.split("/orders/", 1)[1],
                    "total": order["total"], "contact": order["marker"],
                    **({"owner_id": order["owner"]} if version in {"blind-lab/2", "blind-lab/3"} else {})}),
                    "application/json")
            if path == "/admin/export":
                if not who:
                    return self._send(401, "<html>login required</html>")
                return self._send(200, json.dumps(
                    {"export": state["export_marker"]}), "application/json")
            if path == "/admin/users":
                if not who:
                    return self._send(401, "<html>login required</html>")
                if acct.get("role") != "admin":
                    return self._send(403, "<html>forbidden</html>")
                return self._send(200, json.dumps({"users": list(accounts)}),
                                  "application/json")
            if path == "/account/statement":
                return self._send(200, json.dumps(
                    {"statement": state["statement_marker"]}), "application/json")
            if path == "/account/settings":
                if not who:
                    return self._send(401, "<html>login required</html>")
                return self._send(200, json.dumps({"settings": who}),
                                  "application/json")
            if path.startswith(("/docs/", "/safe/docs/")):
                doc = docs.get(path.rsplit("/", 1)[1])
                if doc is None:
                    return self._send(404, json.dumps({"error": "missing"}),
                                      "application/json")
                return self._send(200, json.dumps(doc), "application/json")
            return self._send(404, "<html>not found</html>")

        def _body(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                return json.loads(raw or b"{}")
            except (ValueError, TypeError):
                return {}

        def do_POST(self):
            with lock:
                state["requests"] += 1
            path, who = urlparse(self.path).path, self._who()
            if path in ("/docs", "/safe/docs"):
                if not who:
                    return self._send(401, json.dumps({"error": "login required"}),
                                      "application/json")
                body = self._body()
                doc_seq[0] += 1
                doc_id = f"doc-{doc_seq[0]}"
                safe = path.startswith("/safe")
                docs[doc_id] = {"id": doc_id, "owner": who,
                                "title": str(body.get("title") or "untitled"),
                                "safe": safe}
                return self._send(201, json.dumps(docs[doc_id]),
                                  "application/json")
            return self._send(404, json.dumps({"error": "missing"}),
                              "application/json")

        def do_PUT(self):
            with lock:
                state["requests"] += 1
            path, who = urlparse(self.path).path, self._who()
            if not who:
                return self._send(401, json.dumps({"error": "login required"}),
                                  "application/json")
            doc = docs.get(path.rsplit("/", 1)[1]) \
                if path.startswith(("/docs/", "/safe/docs/")) else None
            if doc is None:
                return self._send(404, json.dumps({"error": "missing"}),
                                  "application/json")
            body = self._body()
            if doc["safe"]:
                # Güvenli ikiz: yalnız sahip yazar, rol alanı yok sayılır.
                if doc["owner"] != who:
                    return self._send(403, json.dumps({"error": "forbidden"}),
                                      "application/json")
                if "title" in body:
                    doc["title"] = str(body["title"])
            else:
                # Zafiyetli ikiz: kimliği olan herkes yazar + rol enjekte eder.
                if "title" in body:
                    doc["title"] = str(body["title"])
                if "role" in body:
                    doc["role"] = str(body["role"])
            return self._send(200, json.dumps(doc), "application/json")

    return Handler, state


def serve(seed: int, port: int = 0, *, version: str = "blind-lab/1"):
    handler, state = make_lab(seed, version=version)
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.blind_state = state  # type: ignore[attr-defined]
    return server
