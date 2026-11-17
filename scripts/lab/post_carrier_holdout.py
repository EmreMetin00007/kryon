"""Independent ephemeral POST form/JSON SQLi+SSTI lab; evaluator truth stays on host.

Exposes POST form-urlencoded SQLi cases and POST JSON SSTI cases with an
unauthorized decoy POST form. Evaluator truth and private readonly_operations
declarations never enter the solver runtime.
"""
from __future__ import annotations

import hashlib
import html
import json
import random
import secrets
import sqlite3
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

import jinja2

FAMILY = "post-carrier-injection"
VERSION = "post-carrier/1"


def declaration(state: dict, base: str) -> dict:
    """Build host-private readonly_operations policy from lab blind_state."""
    root = base.rstrip("/")
    operations = []
    for case in state["truth"]:
        operations.append({
            "method": "POST",
            "url": root + case["path"],
            "operation_id": case["operation_id"],
            "carriers": [case["carrier"]],
            "read_only": True,
            "test_data_only": True,
        })
    return {"readonly_operations": operations}


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
    data = tuple(
        value
        for term in ("alpha", "beta", "gamma")
        for value in (term, secrets.token_hex(64), "synthetic-post-item")
    )
    relation = "WITH inventory(term,memo,category) AS (VALUES (?,?,?),(?,?,?),(?,?,?)) "

    form_catalogs = ["/lookup/" + secrets.token_hex(6) for _ in range(2)]
    json_catalog = "/json/" + secrets.token_hex(6)
    routes: dict[str, dict] = {}
    truth: list[dict] = []

    sql_modes = [
        "concatenated", "concatenated", "concatenated", "concatenated",
        "parameterized", "parameterized", "validated", "validated",
    ]
    rng.shuffle(sql_modes)
    form_cases: dict[str, list[str]] = {cat: [] for cat in form_catalogs}
    for idx, mode in enumerate(sql_modes):
        catalog = form_catalogs[idx % len(form_catalogs)]
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{catalog}/{identifier}"
        op_id = f"op-post-form-{idx}"
        routes[path] = {"class": "sql_injection", "carrier": "form", "mode": mode}
        form_cases[catalog].append(path)
        truth.append({
            "case": identifier,
            "family": FAMILY,
            "path": path,
            "operation_id": op_id,
            "class": "sql_injection",
            "method": "POST",
            "carrier": "form",
            "param": "term",
            "baseline": "alpha",
            "expected": "positive" if mode == "concatenated" else "negative",
            "negative_behavior": None if mode == "concatenated" else mode,
        })

    ssti_modes = [
        "rendered", "rendered", "rendered", "rendered",
        "escaped", "escaped", "validated", "validated",
    ]
    rng.shuffle(ssti_modes)
    json_cases: list[dict] = []
    for idx, mode in enumerate(ssti_modes):
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{json_catalog}/{identifier}"
        op_id = f"op-post-json-{idx}"
        routes[path] = {"class": "ssti", "carrier": "json", "mode": mode}
        json_cases.append({
            "url": path,
            "method": "POST",
            "json_body": {"name": "World"},
        })
        truth.append({
            "case": identifier,
            "family": FAMILY,
            "path": path,
            "operation_id": op_id,
            "class": "ssti",
            "method": "POST",
            "carrier": "json",
            "param": "name",
            "baseline": "World",
            "expected": "positive" if mode == "rendered" else "negative",
            "negative_behavior": None if mode == "rendered" else mode,
        })

    rng.shuffle(truth)
    lock = threading.Lock()
    state = {
        "accounts": accounts,
        "requests": 0,
        "lock": lock,
        "db": db,
        "lab_version": VERSION,
        "truth": truth,
        "wire": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(
            self,
            status: int,
            payload,
            *,
            content_type: str = "",
            body_text: str = "",
            sql_rows=None,
            sql_error=None,
        ) -> None:
            raw = payload.encode() if isinstance(payload, str) else json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode()
            with lock:
                state["requests"] += 1
                state["wire"].append({
                    "sequence": state["requests"],
                    "method": self.command,
                    "path": urlsplit(self.path).path,
                    "request_path": self.path,
                    "content_type": content_type,
                    "request_body": body_text,
                    "status": status,
                    "response_length": len(raw),
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                    "response": payload,
                    "sql_rows": sql_rows,
                    "sql_error": sql_error,
                })
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if isinstance(payload, str) else "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                links = "".join(
                    f'<a href="{cat}">Forms {idx + 1}</a> '
                    for idx, cat in enumerate(form_catalogs)
                )
                body = (
                    "<html><body>POST Surface member-a "
                    f"{links}"
                    f'<a href="{json_catalog}">JSON Actions</a>'
                    "</body></html>"
                )
                return self._send(200, body)
            if parsed.path in form_cases:
                forms_html = "".join(
                    f'<form action="{path}" method="POST"><input name="term" value="alpha"></form>'
                    for path in form_cases[parsed.path]
                )
                if parsed.path == form_catalogs[0]:
                    forms_html += '<form action="/lookup/unauthorized" method="POST"><input name="term" value="alpha"></form>'
                return self._send(200, f"<html><body>{forms_html}</body></html>")
            if parsed.path == json_catalog:
                return self._send(200, {"actions": json_cases})
            return self._send(404, {"error": "missing"})

        def do_POST(self):
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body_text = self.rfile.read(length).decode("utf-8", "replace")
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, {"error": "missing"}, content_type=ctype, body_text=body_text)
            mode = route["mode"]
            if route["class"] == "sql_injection":
                if ctype != "application/x-www-form-urlencoded":
                    return self._send(415, {"error": "expected form"}, content_type=ctype, body_text=body_text)
                params = parse_qsl(body_text, keep_blank_values=True)
                if len(params) != 1 or params[0][0] != "term" or len(params[0][1]) > 256:
                    return self._send(400, {"error": "invalid input"}, content_type=ctype, body_text=body_text)
                value = params[0][1]
                bindings = data
                if mode == "validated" and value not in {"alpha", "beta", "gamma"}:
                    return self._send(400, {"error": "invalid input"}, content_type=ctype, body_text=body_text)
                if mode == "parameterized":
                    predicate = "term = ?"
                    bindings += (value,)
                else:
                    predicate = "term = '" + value + "'"
                query = relation + "SELECT term,memo,category FROM inventory WHERE " + predicate
                try:
                    with lock:
                        rows = [list(row) for row in db.execute(query, bindings).fetchall()]
                    return self._send(
                        200,
                        {"records": rows},
                        content_type=ctype,
                        body_text=body_text,
                        sql_rows=rows,
                    )
                except sqlite3.Error as exc:
                    return self._send(
                        400,
                        {"error": "invalid input"},
                        content_type=ctype,
                        body_text=body_text,
                        sql_error=type(exc).__name__,
                    )
            if ctype != "application/json":
                return self._send(415, {"error": "expected json"}, content_type=ctype, body_text=body_text)
            try:
                doc = json.loads(body_text)
            except ValueError:
                return self._send(400, {"error": "invalid json"}, content_type=ctype, body_text=body_text)
            if not isinstance(doc, dict) or not isinstance(doc.get("name"), str) or len(doc["name"]) > 256:
                return self._send(400, {"error": "invalid input"}, content_type=ctype, body_text=body_text)
            value = doc["name"]
            if mode == "validated":
                if not all(c.isalnum() or c in " .-_" for c in value):
                    return self._send(400, {"error": "invalid template input"}, content_type=ctype, body_text=body_text)
                return self._send(200, {"result": "Hello " + value, "template": "validated"}, content_type=ctype, body_text=body_text)
            if mode == "escaped":
                return self._send(200, {"result": "Hello " + html.escape(value), "template": "escaped"}, content_type=ctype, body_text=body_text)
            try:
                env = jinja2.Environment(autoescape=False)
                rendered = env.from_string(value).render()
                return self._send(200, {"result": rendered, "template": "rendered"}, content_type=ctype, body_text=body_text)
            except jinja2.TemplateError:
                return self._send(400, {"error": "template syntax error"}, content_type=ctype, body_text=body_text)

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def evidence_matches(case: dict, record: dict, wire: list[dict], target: str) -> tuple[str, list[int]]:
    """Exact POST request/body/response verification before metric credit."""
    origin = urlsplit(target)
    context = record.get("execution_context", {})
    if (
        context.get("vuln_class") != case["class"]
        or context.get("param") != case["param"]
        or context.get("method") != "POST"
        or context.get("carrier") != case["carrier"]
    ):
        return "POST carrier request context mismatch", []
    expected_ctype = (
        "application/x-www-form-urlencoded"
        if case["carrier"] == "form"
        else "application/json"
    )
    roles, sequences, requests = {}, [], []
    used_sequences: set[int] = set()
    for response in record.get("request_evidence", []):
        url = urlsplit(response.get("request_url", ""))
        matches = [
            row
            for row in wire
            if row["method"] == response.get("method") == "POST"
            and row["path"] == case["path"] == url.path
            and row.get("content_type") == expected_ctype
            and row["status"] == response.get("status")
            and row["response_length"] == response.get("response_length")
            and row["response_sha256"] == response.get("response_sha256")
        ]
        if (
            not response.get("transport_ok")
            or not matches
            or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)
        ):
            return "POST HTTP evidence does not match exact evaluator wire", []
        unused = [m for m in matches if m["sequence"] not in used_sequences]
        chosen = unused[0] if unused else matches[0]
        used_sequences.add(chosen["sequence"])
        roles[response["role"]] = chosen
        sequences.append(chosen["sequence"])
        requests.append(chosen)
    confirmed = record["verdict"] == "CONFIRMED"
    if case["class"] == "sql_injection":
        if record.get("oracle") != "differential_boolean":
            return "POST SQLi holdout requires differential_boolean oracle", []
        required = {"baseline", "true-1", "false-1", "false-2", "true-2"} if confirmed else {"baseline-1", "baseline-2"}
        if not required <= roles.keys():
            return "missing POST SQL baseline or differential controls", []
        baseline = roles["baseline" if confirmed else "baseline-1"]
        if baseline["status"] != 200 or not baseline.get("sql_rows") or baseline.get("sql_error"):
            return "POST SQL baseline must return actual nonempty SELECT rows", []
        path_wire = [
            row
            for row in wire
            if row["method"] == "POST" and row["path"] == case["path"] and row.get("content_type") == expected_ctype
        ]
        if confirmed:
            evidence = record.get("evidence", {})
            if (
                len(evidence.get("rounds", [])) != 2
                or not all(row.get("confirmed") for row in evidence["rounds"])
                or evidence.get("baseline_stability", 0) < 0.95
            ):
                return "POST SQL differential did not repeat with stable baseline", []
            true_rows = [
                row for row in path_wire
                if dict(parse_qsl(row["request_body"], keep_blank_values=True)).get(case["param"])
                == evidence.get("true_payload")
                and row["status"] == 200
                and row.get("sql_rows") == baseline["sql_rows"]
                and not row.get("sql_error")
                and row["response_sha256"] == roles["true-1"]["response_sha256"]
            ]
            false_rows = [
                row for row in path_wire
                if dict(parse_qsl(row["request_body"], keep_blank_values=True)).get(case["param"])
                == evidence.get("false_payload")
                and row["status"] == 200
                and row.get("sql_rows") == []
                and not row.get("sql_error")
                and row["response_sha256"] == roles["false-1"]["response_sha256"]
            ]
            if len(true_rows) < 2 or len(false_rows) < 2:
                return "signed POST SQL payload does not match wire", []
            t1, t2 = true_rows[-2], true_rows[-1]
            f1, f2 = false_rows[-2], false_rows[-1]
            if not (t1["sequence"] < f1["sequence"] < f2["sequence"] < t2["sequence"]):
                return "POST SQL differential round ordering does not match wire", []
            sequences = [baseline["sequence"], t1["sequence"], f1["sequence"], f2["sequence"], t2["sequence"]]
        else:
            if (
                baseline["sql_rows"] != roles["baseline-2"].get("sql_rows")
                or roles["baseline-2"]["status"] != 200
                or len(sequences) != 6
            ):
                return "negative POST SQL controls incomplete", []
            value = case["baseline"]
            required_values = [
                value, value, value + " AND 1=1", value + " AND 1=2",
                value + "' AND '1'='1", value + "' AND '1'='2",
            ]
            if [
                dict(parse_qsl(row["request_body"], keep_blank_values=True)).get(case["param"])
                for row in requests
            ] != required_values:
                return "negative POST SQL boolean pairs incomplete", []
            if any(row["status"] not in {200, 400, 422} for row in roles.values()):
                return "negative POST SQL control failed", []
        return "", sequences

    if record.get("oracle") != "arithmetic_eval":
        return "POST SSTI holdout requires arithmetic_eval oracle", []
    if confirmed:
        required = {"baseline", "ssti-probe-1", "ssti-probe-2", "ssti-malformed-control"}
        if not required <= roles.keys():
            return "missing POST SSTI baseline or arithmetic controls", []
        if roles["baseline"]["status"] != 200:
            return "POST SSTI baseline must return status 200", []
        operands = record.get("evidence", {}).get("operands", [])
        if len(operands) != 2:
            return "POST SSTI operands missing from evidence", []
        (a, b), (a2, b2) = operands[0], operands[1]
        r1_text = json.dumps(roles["ssti-probe-1"].get("response", ""))
        r2_text = json.dumps(roles["ssti-probe-2"].get("response", ""))
        if str(a * b) not in r1_text or f"{a}*{b}" in r1_text:
            return "POST SSTI probe 1 did not evaluate arithmetic product", []
        if str(a2 * b2) not in r2_text or f"{a2}*{b2}" in r2_text:
            return "POST SSTI probe 2 did not evaluate arithmetic product", []
        malformed_resp = roles["ssti-malformed-control"]
        if malformed_resp["status"] not in {200, 400, 422}:
            return "POST SSTI malformed control status failed", []
        if str(a * b) in json.dumps(malformed_resp.get("response", "")):
            return "POST SSTI malformed control evaluated unexpectedly", []
    else:
        if len(sequences) != 7:
            return "negative POST SSTI controls incomplete", []
        if any(row["status"] not in {200, 400, 422} for row in requests):
            return "negative POST SSTI control failed", []
    return "", sequences
