"""Independent ephemeral SQLite SELECT lab; evaluator truth stays on the host.

The fresh in-memory database reads a synthetic relation supplied by a bound
VALUES CTE. Even initialization uses no SQL writes. An authorizer denies
everything except SELECT, READ and the bounded functions used by the query.
"""
from __future__ import annotations

import hashlib
import json
import random
import secrets
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

FAMILY = "readonly-sql-injection"
VERSION = "readonly-sqli/1"
CONTEXTS = ("numeric", "single-quoted")


def serve(seed: int, port: int = 0):
    if type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("holdout seed must be an unsigned 63-bit integer")
    rng = random.Random(seed)
    accounts = {"member-a": {"token": secrets.token_urlsafe(32), "role": "member"}}
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in {
        sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
    } else sqlite3.SQLITE_DENY)
    db.set_progress_handler(lambda: 1, 10000)
    # Stable substantial rows make the boolean oracle measure database output,
    # rather than parameter reflection or generic application messages.
    data = tuple(value for ident in (1, 2, 3) for value in (
        ident, secrets.token_hex(128), "synthetic-inventory"))
    relation = "WITH inventory(id,memo,category) AS (VALUES (?,?,?),(?,?,?),(?,?,?)) "
    routes, catalogs, truth = {}, {}, []
    for context in CONTEXTS * 2:
        catalog = "/lookup/" + secrets.token_hex(8)
        modes = ["concatenated", "concatenated", "parameterized", "validated"]
        rng.shuffle(modes)
        catalogs[catalog] = []
        for mode in modes:
            identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            path = catalog + "/" + identifier
            routes[path] = {"context": context, "mode": mode}
            catalogs[catalog].append(path)
            truth.append({"case": identifier, "family": FAMILY, "path": path,
                          "class": "sql_injection", "param": "id", "baseline": "1",
                          "context": context, "expected": "positive" if mode == "concatenated" else "negative",
                          "negative_behavior": None if mode == "concatenated" else mode})
    rng.shuffle(truth)
    lock = threading.Lock()
    state = {"accounts": accounts, "requests": 0, "lock": lock, "db": db,
             "lab_version": VERSION, "truth": truth, "wire": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status, payload, *, query=None, parameters=(), rows=None, error=None):
            raw = payload.encode() if isinstance(payload, str) else json.dumps(
                payload, sort_keys=True, separators=(",", ":")).encode()
            with lock:
                state["requests"] += 1
                state["wire"].append({"sequence": state["requests"], "method": self.command,
                                      "path": urlsplit(self.path).path, "request_path": self.path,
                                      "status": status, "response_length": len(raw),
                                      "response_sha256": hashlib.sha256(raw).hexdigest(),
                                      "response": payload, "query": query,
                                      "parameters": list(parameters), "sql_rows": rows, "sql_error": error})
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if isinstance(payload, str) else "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/" or parsed.path in catalogs:
                links = list(catalogs) if parsed.path == "/" else [route + "?id=1" for route in catalogs[parsed.path]]
                return self._send(200, "<html><body>Inventory member-a " + " ".join(
                    '<a href="' + route + '">Browse</a>' for route in links) + "</body></html>")
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, {"error": "missing"})
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if len(params) != 1 or params[0][0] != "id" or len(params[0][1]) > 256:
                return self._send(400, {"error": "invalid input"})
            value = params[0][1]
            mode, context = route["mode"], route["context"]
            bindings = data
            if mode == "validated" and value not in {"1", "2", "3"}:
                return self._send(400, {"error": "invalid input"})
            if mode == "parameterized":
                predicate = "id = CAST(? AS INTEGER)"
                bindings += (value,)
            else:
                predicate = {"numeric": "id = " + value,
                             "single-quoted": "CAST(id AS TEXT) = '" + value + "'",
                             "double-quoted": 'CAST(id AS TEXT) = "' + value + '"',
                             "parenthesized": "id = (" + value + ")"}[context]
            query = relation + "SELECT id,memo,category FROM inventory WHERE " + predicate
            try:
                with lock:
                    rows = [list(row) for row in db.execute(query, bindings).fetchall()]
                return self._send(200, {"records": rows}, query=query, parameters=bindings, rows=rows)
            except sqlite3.Error as exc:
                # Generic text cannot establish SQLi; actual database errors
                # remain private so the solver must use a boolean oracle.
                return self._send(400, {"error": "invalid input"}, query=query,
                                  parameters=bindings, error=type(exc).__name__)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def evidence_matches(case, record, wire, target):
    """Exact request/response and actual SELECT result gate, before metric credit."""
    origin = urlsplit(target)
    context = record.get("execution_context", {})
    if (context.get("vuln_class") != "sql_injection" or context.get("param") != case["param"]
            or context.get("method") != "GET" or context.get("carrier") != "query"):
        return "SQL request context mismatch", []
    roles, sequences, requests = {}, [], []
    for response in record.get("request_evidence", []):
        url = urlsplit(response.get("request_url", ""))
        matches = [row for row in wire if row["method"] == response.get("method") == "GET"
                   and row["path"] == case["path"] == url.path
                   and parse_qsl(urlsplit(row["request_path"]).query, keep_blank_values=True)
                   == parse_qsl(url.query, keep_blank_values=True)
                   and row["status"] == response.get("status")
                   and row["response_length"] == response.get("response_length")
                   and row["response_sha256"] == response.get("response_sha256")]
        if (not response.get("transport_ok") or not matches
                or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)):
            return "SQL HTTP evidence does not match exact evaluator wire", []
        roles[response["role"]] = matches[0]
        sequences.append(matches[0]["sequence"])
        requests.append(matches[0])
    confirmed = record["verdict"] == "CONFIRMED"
    required = {"baseline", "true-1", "false-1", "false-2", "true-2"} if confirmed else {"baseline-1", "baseline-2"}
    if not required <= roles.keys():
        return "missing SQL baseline or differential controls", []
    baseline = roles["baseline" if confirmed else "baseline-1"]
    if baseline["status"] != 200 or not baseline.get("sql_rows") or baseline.get("sql_error"):
        return "SQL baseline must return actual nonempty SELECT rows", []
    if record.get("oracle") != "differential_boolean":
        return "read-only SQL holdout requires the boolean oracle", []
    if confirmed:
        evidence = record.get("evidence", {})
        if (len(evidence.get("rounds", [])) != 2 or not all(row.get("confirmed") for row in evidence["rounds"])
                or evidence.get("baseline_stability", 0) < 0.95):
            return "SQL differential did not repeat with stable baseline", []
        for role in ("true-1", "true-2"):
            row = roles[role]
            if row["status"] != 200 or row.get("sql_rows") != baseline["sql_rows"] or row.get("sql_error"):
                return "TRUE control must return baseline SELECT rows", []
        for role in ("false-1", "false-2"):
            row = roles[role]
            if row["status"] != 200 or row.get("sql_rows") != [] or row.get("sql_error"):
                return "FALSE control must execute an empty SELECT result", []
        for role, key in (("true-1", "true_payload"), ("true-2", "true_payload"),
                          ("false-1", "false_payload"), ("false-2", "false_payload")):
            if dict(parse_qsl(urlsplit(roles[role]["request_path"]).query))[case["param"]] != evidence.get(key):
                return "signed SQL payload does not match wire", []
    else:
        if (baseline["sql_rows"] != roles["baseline-2"].get("sql_rows")
                or roles["baseline-2"]["status"] != 200 or len(sequences) != 6):
            return "negative SQL controls incomplete", []
        value = case["baseline"]
        required_values = [value, value, value + " AND 1=1", value + " AND 1=2",
                           value + "' AND '1'='1", value + "' AND '1'='2"]
        if [dict(parse_qsl(urlsplit(row["request_path"]).query)).get(case["param"])
                for row in requests] != required_values:
            return "negative SQL boolean pairs incomplete", []
        if any(row["status"] not in {200, 400, 422} for row in roles.values()):
            return "negative SQL control failed", []
    return "", sequences
