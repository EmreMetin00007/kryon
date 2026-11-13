"""Independent, ephemeral GET-only authorization lab; host-owned truth only.

Unlike blind-lab, this service has no injection/redirect/browser endpoints.
Opaque record URLs are learned from each synthetic account's index. Every
record is private to its owner; some handlers omit the authenticated owner
check. Neither route names nor response metadata disclose that omission.
"""
from __future__ import annotations

import hashlib
import json
import random
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

FAMILY = "readonly-api-access-control"
VERSION = "readonly-api-access/1"


def serve(seed: int, port: int = 0):
    if type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("holdout seed must be an unsigned 63-bit integer")
    rng = random.Random(seed)
    accounts = {name: {"token": secrets.token_urlsafe(32), "role": "member"}
                for name in ("member-a", "member-b", "member-c", "member-d")}
    tokens = {account["token"]: name for name, account in accounts.items()}
    records, truth = {}, []
    for owner in accounts:
        modes = ["missing-owner-check", "missing-owner-check", "deny", "redact"]
        rng.shuffle(modes)
        for mode in modes:
            identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            path = "/api/records/" + identifier
            body = {"id": identifier, "owner_id": owner,
                    "memo": secrets.token_hex(24), "amount": rng.randrange(10, 500)}
            records[path] = {"owner": owner, "mode": mode, "body": body}
            truth.append({"case": identifier, "family": FAMILY, "path": path,
                          "class": "bola", "owner": owner, "marker": identifier,
                          "denied_identities": [name for name in accounts if name != owner],
                          "expected": "positive" if mode == "missing-owner-check" else "negative",
                          "negative_behavior": mode if mode != "missing-owner-check" else None})
    rng.shuffle(truth)
    lock = threading.Lock()
    state = {"accounts": accounts, "requests": 0, "lock": lock,
             "lab_version": VERSION, "truth": truth, "wire": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status, payload, actor, method):
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            with lock:
                state["requests"] += 1
                state["wire"].append({"sequence": state["requests"], "method": method,
                                      "path": self.path, "identity": actor or "anonymous",
                                      "status": status, "response_length": len(raw),
                                      "response_sha256": hashlib.sha256(raw).hexdigest(),
                                      "response": payload})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(raw)

        def do_GET(self):
            token = self.headers.get("Authorization", "").removeprefix("Bearer ")
            actor = tokens.get(token)
            path = urlsplit(self.path).path
            if path == "/":
                payload = {"service": "record archive", "links": []}
                if actor:
                    payload.update(current_user={"id": actor}, records=[
                        {"id": record["body"]["id"], "owner_id": actor, "href": route}
                        for route, record in records.items() if record["owner"] == actor])
                return self._send(200, payload, actor, "GET")
            record = records.get(path)
            if not record:
                return self._send(404, {"error": "missing"}, actor, "GET")
            if not actor:
                return self._send(401, {"error": "unauthorized"}, actor, "GET")
            if actor == record["owner"] or record["mode"] == "missing-owner-check":
                return self._send(200, record["body"], actor, "GET")
            if record["mode"] == "redact":
                # A 200 response alone is never evidence of owner-data access.
                return self._send(200, {"access": "restricted", "record": None}, actor, "GET")
            return self._send(403, {"error": "forbidden"}, actor, "GET")

        def _deny_mutation(self):
            return self._send(405, {"error": "read only"}, None, self.command)

        do_POST = do_PUT = do_PATCH = do_DELETE = do_CONNECT = do_TRACE = _deny_mutation

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state  # The launcher's host-only session/accounting API.
    return server
