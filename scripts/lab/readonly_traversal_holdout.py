"""Independent path normalization lab with actual, bounded synthetic file reads.

Only the host owns this module, fixture tree, declarations and truth. The HTTP
surface exposes opaque catalog links and benign filename samples, never paths
to private files or evaluator labels. No handler opens an undeclared file.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import re
import secrets
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, unquote, urlsplit

FAMILY = "readonly-path-traversal"
VERSION = "readonly-traversal/1"


def resolve_fixture(root, public, value, mode, allowed):
    """Normalize first, enforce fixture/allowlist boundaries before any open."""
    if not isinstance(value, str) or not value or len(value) > 256 or "\x00" in value:
        return None
    if mode == "decoded-join":
        value = unquote(value).replace("\\", "/")
    if Path(value).is_absolute():
        return None
    candidate = (public / value).resolve()
    if not candidate.is_relative_to(root) or candidate not in allowed:
        return None
    if mode == "contained" and not candidate.is_relative_to(public):
        return None
    if mode == "allowlisted" and value != "notes.txt":
        return None
    return candidate


def serve(seed: int, port: int = 0, *, fixture_parent=None):
    if type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("holdout seed must be an unsigned 63-bit integer")
    rng = random.Random(seed)
    fixtures = tempfile.TemporaryDirectory(prefix="traversal-fixtures-", dir=fixture_parent or "/tmp/cco-work")
    root = Path(fixtures.name).resolve()
    routes, catalogs, truth = {}, {}, []
    for depth in (1, 2, 1, 2):
        catalog = "/files/" + secrets.token_hex(8)
        modes = ["normalized-join", "decoded-join", "contained", "allowlisted"]
        rng.shuffle(modes)
        catalogs[catalog] = []
        for mode in modes:
            identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            path = catalog + "/" + identifier
            boundary = root / identifier
            public = boundary / "public"
            if depth == 2:
                public /= "nested"
            private = boundary / "private"
            public.mkdir(parents=True)
            private.mkdir()
            canary = private / ("fixture-" + secrets.token_hex(8) + ".txt")
            benign = public / "notes.txt"
            marker = "synthetic-fixture-" + secrets.token_hex(32)
            benign.write_text("Synthetic public application note. " + secrets.token_hex(64))
            canary.write_text("Synthetic private test fixture. " + marker)
            traversal = "../" * depth + "private/" + canary.name
            routes[path] = {"public": public, "mode": mode, "allowed": {benign, canary}}
            catalogs[catalog].append(path)
            truth.append({"case": identifier, "family": FAMILY, "path": path,
                          "class": "path_traversal", "param": "file", "baseline": "notes.txt",
                          "traversal": traversal, "marker": marker, "depth": depth,
                          "fixture_file": str(canary.relative_to(root)),
                          "public_file": str(benign.relative_to(root)),
                          "expected": "positive" if mode.endswith("join") else "negative",
                          "normalization": mode})
    rng.shuffle(truth)
    lock = threading.Lock()
    state = {"accounts": {"member-a": {"token": secrets.token_urlsafe(32), "role": "member"}},
             "requests": 0, "lock": lock, "truth": truth, "wire": [], "lab_version": VERSION,
             "fixture_root": root, "fixtures": fixtures, "routes": routes}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status, payload, *, read_path=None):
            raw = payload.encode()
            with lock:
                state["requests"] += 1
                state["wire"].append({"sequence": state["requests"], "method": self.command,
                    "path": urlsplit(self.path).path, "request_path": self.path,
                    "status": status, "response_length": len(raw), "response": payload,
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                    "read_file": str(read_path.relative_to(root)) if read_path else None})
            self.send_response(status)
            self.send_header("Content-Type", "text/html" if payload.startswith("<html>") else "text/plain")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/" or parsed.path in catalogs:
                links = list(catalogs) if parsed.path == "/" else [p + "?file=notes.txt" for p in catalogs[parsed.path]]
                return self._send(200, "<html><body>Application files member-a " + " ".join(
                    '<a href="' + link + '">Browse</a>' for link in links) + "</body></html>")
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, "missing endpoint")
            params = parse_qsl(parsed.query, keep_blank_values=True)
            if len(params) != 1 or params[0][0] != "file":
                return self._send(400, "invalid input")
            candidate = resolve_fixture(root, route["public"], params[0][1], route["mode"], route["allowed"])
            if candidate is None:
                return self._send(404, "fixture unavailable")
            # The tree is host-owned, immutable during traffic, with no symlinks.
            return self._send(200, candidate.read_text(), read_path=candidate)

        def _deny_mutation(self):
            return self._send(405, "read-only fixture")

        do_POST = do_PUT = do_PATCH = do_DELETE = _deny_mutation

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def declaration(state, target):
    return {"mode": "application_files", "files": [
        {"url": target.rstrip("/") + case["path"], "param": case["param"], "carrier": "query",
         "path": case["traversal"], "marker": case["marker"], "test_data_only": True, "outside_root": True}
        for case in state["truth"]]}


def evidence_matches(case, record, wire, target):
    """Require exact signed controls AND actual reads inside fixture boundaries."""
    context = record.get("execution_context", {})
    if (context.get("vuln_class") != "path_traversal" or context.get("param") != case["param"]
            or context.get("method") != "GET" or context.get("carrier") != "query"
            or record.get("oracle") != "file_signature"):
        return "traversal request context mismatch", []
    roles, sequences = {}, []
    origin = urlsplit(target)
    required = ["baseline", "direct-name", "missing-file", "traversal-probe", "traversal-repeat"]
    responses = record.get("request_evidence", [])
    if [row.get("role") for row in responses] != required:
        return "missing or duplicated traversal controls", []
    for response in responses:
        url = urlsplit(response.get("request_url", ""))
        matches = [row for row in wire if row["method"] == response.get("method") == "GET"
                   and row["path"] == case["path"] == url.path
                   and parse_qsl(urlsplit(row["request_path"]).query, keep_blank_values=True)
                   == parse_qsl(url.query, keep_blank_values=True)
                   and row["status"] == response.get("status")
                   and row["response_length"] == response.get("response_length")
                   and row["response_sha256"] == response.get("response_sha256")
                   and hashlib.sha256(row["response"].encode()).hexdigest() == row["response_sha256"]
                   and len(row["response"].encode()) == row["response_length"]
                   and row["sequence"] not in sequences]
        if (not response.get("transport_ok") or not matches
                or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)):
            return "traversal HTTP evidence does not match exact evaluator wire", []
        roles[response["role"]] = matches[0]
        sequences.append(matches[0]["sequence"])
    values = {role: dict(parse_qsl(urlsplit(row["request_path"]).query)).get(case["param"])
              for role, row in roles.items()}
    missing = values["missing-file"] or ""
    if (values["baseline"] != case["baseline"]
            or values["direct-name"] != case["traversal"].rsplit("/", 1)[-1]
            or missing.rsplit("/", 1)[0] != case["traversal"].rsplit("/", 1)[0]
            or not re.fullmatch(r"cco-missing-[0-9a-f]{16}\.txt", missing.rsplit("/", 1)[-1])
            or values["traversal-probe"] != case["traversal"]
            or values["traversal-repeat"] != case["traversal"]):
        return "traversal control payload mismatch", []
    if (roles["baseline"]["status"] != 200 or roles["baseline"]["read_file"] != case["public_file"]
            or any(case["marker"] in roles[role]["response"] for role in required[:3])
            or any(roles[role]["status"] != 404 or roles[role]["read_file"] for role in required[1:3])):
        return "traversal baseline/direct/missing boundary not established", []
    confirmed = record.get("verdict") == "CONFIRMED"
    for role in required[3:]:
        row = roles[role]
        if confirmed:
            if (row["status"] != 200 or row["read_file"] != case["fixture_file"]
                    or case["marker"] not in row["response"]):
                return "repeated synthetic fixture read not established", []
        elif row["status"] != 404 or row["read_file"] or case["marker"] in row["response"]:
            return "secure traversal negative controls incomplete", []
    if confirmed and (record.get("evidence", {}).get("marker_sha256") != hashlib.sha256(case["marker"].encode()).hexdigest()
                      or record["evidence"].get("payload") != case["traversal"]):
        return "declared traversal marker binding mismatch", []
    return "", sequences
