"""Independent ephemeral SPA Discovery + Reflected-XSS + Stateful Business Logic holdout lab.

Exposes a pure SPA shell at `/` (zero `<a href>` API links in initial HTML; routes
appear only in `/assets/app.<hex>.js`, SPA hash/router definitions, and
`/assets/spec-<hex>.json`) covering:
  - 8 SPA-discovered reflected-XSS cases (4 rendered HTML + 4 escaped/stripped negatives)
  - 8 SPA-discovered stateful business-logic cases (4 vulnerable + 4 protected across
    idempotency_replay, sequence_step_skip, schema_symmetry)
  - 1 unauthorized mutating decoy `/biz/decoy/unauthorized` omitted from private policy.

Evaluator truth and private `business_logic_operations` declarations stay on host.
"""
from __future__ import annotations

import copy
import hashlib
import html
import json
import random
import re
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

from lab import readonly_xss_redirect_holdout

FAMILY = "spa-business-logic"
VERSION = "spa-business/1"


def declaration(state: dict, base: str) -> dict:
    """Build host-private business_logic_operations policy from lab blind_state."""
    root = base.rstrip("/")
    operations = []
    for case in state["truth"]:
        if case["class"] != "business_logic":
            continue
        operations.append({
            "method": case["method"],
            "url": root + case["path"],
            "operation_id": case["operation_id"],
            "kind": case["kind"],
            "carriers": [case["carrier"]],
            "allow_state_mutation": True,
            "test_data_only": True,
        })
    return {"business_logic_operations": operations}


def serve(seed: int, port: int = 0):
    if type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("holdout seed must be an unsigned 63-bit integer")
    rng = random.Random(seed)
    accounts = {"member-a": {"token": secrets.token_urlsafe(32), "role": "member"}}

    bundle_name = f"/assets/app.{secrets.token_hex(4)}.js"
    spec_name = f"/assets/spec-{secrets.token_hex(4)}.json"
    xss_catalogs = ["/xss/" + secrets.token_hex(6) for _ in range(2)]
    biz_catalogs = {
        "idempotency_replay": "/biz/coupon",
        "sequence_step_skip": "/biz/workflow",
        "schema_symmetry": "/biz/tag",
    }

    routes: dict[str, dict] = {}
    biz_objects: dict[str, dict] = {}
    truth: list[dict] = []

    xss_modes = [
        "rendered_html", "rendered_html", "rendered_html", "rendered_html",
        "html_escaped", "html_escaped", "tag_stripped", "tag_stripped",
    ]
    rng.shuffle(xss_modes)
    js_lines = [
        f"const SPEC_URL = '{spec_name}';",
        *[f"const XSS_ROOT_{i} = '{cat}';" for i, cat in enumerate(xss_catalogs)],
    ]
    xss_view_routes: dict[str, list[str]] = {cat: [] for cat in xss_catalogs}
    for idx, mode in enumerate(xss_modes):
        cat = xss_catalogs[idx % len(xss_catalogs)]
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{cat}/{identifier}"
        routes[path] = {"class": "xss_reflected", "mode": mode}
        xss_view_routes[cat].append(f"{path}?q=hello")
        if idx < 4:
            js_lines.append(f"fetch('{path}?q=hello');")
        else:
            js_lines.append(f"router.push('#{path}?q=hello');")
        truth.append({
            "case": identifier,
            "family": FAMILY,
            "path": path,
            "class": "xss_reflected",
            "method": "GET",
            "carrier": "query",
            "param": "q",
            "baseline": "hello",
            "expected": "positive" if mode == "rendered_html" else "negative",
            "negative_behavior": None if mode == "rendered_html" else mode,
        })

    biz_specs = [
        ("idempotency_replay", "POST", True),
        ("idempotency_replay", "POST", True),
        ("idempotency_replay", "POST", False),
        ("idempotency_replay", "POST", False),
        ("sequence_step_skip", "POST", True),
        ("sequence_step_skip", "POST", False),
        ("schema_symmetry", "PUT", True),
        ("schema_symmetry", "PUT", False),
    ]
    rng.shuffle(biz_specs)
    openapi_paths: dict[str, dict] = {}

    def _init_obj(kind: str, oid: str) -> dict:
        if kind == "idempotency_replay":
            return {"id": oid, "kind": kind, "uses": 0, "total": 100}
        if kind == "sequence_step_skip":
            return {"id": oid, "kind": kind, "prepared": False, "status": "draft"}
        return {"id": oid, "kind": kind, "title": "initial", "server_tag": "initial"}

    for idx, (kind, meth, vulnerable) in enumerate(biz_specs):
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{biz_catalogs[kind]}/{identifier}"
        op_id = f"op-spa-biz-{idx}"
        routes[path] = {"class": "business_logic", "kind": kind, "method": meth, "vulnerable": vulnerable}
        biz_objects[path] = _init_obj(kind, identifier)
        biz_objects[f"{path}?role=control"] = _init_obj(kind, identifier)
        sample_props = (
            {"op": "redeem", "coupon": "BIZ-ONE"} if kind == "idempotency_replay"
            else ({"op": "complete"} if kind == "sequence_step_skip"
                  else {"op": "server_tag", "server_tag": "val"})
        )
        if idx < 4:
            if meth == "PUT":
                js_lines.append(f"axios.put('{path}', {json.dumps(sample_props)});")
            else:
                js_lines.append(
                    f"fetch('{path}', {{method: 'POST', body: JSON.stringify({json.dumps(sample_props)})}});"
                )
        else:
            openapi_paths[path] = {
                meth.lower(): {
                    "operationId": op_id,
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        k: {"type": "string", "example": v}
                                        for k, v in sample_props.items()
                                    },
                                }
                            }
                        }
                    },
                }
            }
        truth.append({
            "case": identifier,
            "family": FAMILY,
            "path": path,
            "operation_id": op_id,
            "class": "business_logic",
            "kind": kind,
            "method": meth,
            "carrier": "json",
            "param": "op",
            "expected": "positive" if vulnerable else "negative",
            "negative_behavior": None if vulnerable else "enforced_business_invariant",
        })

    # Unauthorized mutating decoy exposed in JS bundle, omitted from private policy.
    decoy_path = "/biz/decoy/unauthorized"
    js_lines.append(f"fetch('{decoy_path}', {{method: 'POST', body: JSON.stringify({{op: 'purge'}})}});")
    app_js = "\n".join(js_lines) + "\n"
    openapi_doc = {
        "openapi": "3.0.0",
        "info": {"title": "SPA Business Holdout API", "version": "1.0.0"},
        "paths": openapi_paths,
    }
    home_html = (
        f'<html><head><script src="{bundle_name}"></script></head>'
        '<body><div id="app">SPA Business Portal member-a</div></body></html>'
    )

    rng.shuffle(truth)
    lock = threading.RLock()
    state = {
        "accounts": accounts,
        "requests": 0,
        "lock": lock,
        "lab_version": VERSION,
        "truth": truth,
        "wire": [],
        "decoy_hits": 0,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(
            self,
            status: int,
            payload,
            *,
            content_type: str = "application/json",
            body_text: str = "",
        ) -> None:
            raw = payload.encode("utf-8") if isinstance(payload, str) else json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
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
                    "response": payload if isinstance(payload, str) else raw.decode("utf-8"),
                })
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                return self._send(200, home_html, content_type="text/html")
            if parsed.path == bundle_name:
                return self._send(200, app_js, content_type="application/javascript")
            if parsed.path == spec_name:
                return self._send(200, json.dumps(openapi_doc), content_type="application/json")
            if parsed.path in xss_view_routes:
                links = " ".join(f'<a href="{href}">Inspect</a>' for href in xss_view_routes[parsed.path])
                return self._send(200, f"<html><body>{links}</body></html>", content_type="text/html")
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, "missing endpoint", content_type="text/plain")
            if route["class"] == "xss_reflected":
                params = parse_qsl(parsed.query, keep_blank_values=True)
                if len(params) != 1 or params[0][0] != "q" or len(params[0][1]) > 256:
                    return self._send(400, "<html><body>invalid input</body></html>", content_type="text/html")
                value = params[0][1]
                mode = route["mode"]
                if mode == "rendered_html":
                    return self._send(200, f"<html><body><div>Search: {value}</div></body></html>", content_type="text/html")
                if mode == "html_escaped":
                    return self._send(
                        200,
                        f"<html><body><div>Search: {html.escape(value)}</div></body></html>",
                        content_type="text/html",
                    )
                cleaned = re.sub(r"[<>\"']", "", value)
                return self._send(200, f"<html><body><div>Search: {cleaned}</div></body></html>", content_type="text/html")

            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            obj_key = f"{parsed.path}?role=control" if qs.get("role") == "control" else parsed.path
            with lock:
                obj = copy.deepcopy(biz_objects.get(obj_key))
            if obj is None:
                return self._send(404, {"error": "missing object"})
            return self._send(200, obj)

        def _handle_mutation(self):
            parsed = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if parsed.path == decoy_path:
                with lock:
                    state["decoy_hits"] += 1
                return self._send(200, {"purged": True}, content_type="application/json", body_text=raw_body)
            route = routes.get(parsed.path)
            if not route or route["class"] != "business_logic":
                return self._send(404, {"error": "missing endpoint"}, body_text=raw_body)
            if self.command != route["method"] or ctype != "application/json":
                return self._send(405, {"error": "method or content-type not allowed"}, body_text=raw_body)
            try:
                data = json.loads(raw_body or "{}")
            except ValueError:
                return self._send(400, {"error": "invalid json"}, body_text=raw_body)
            if not isinstance(data, dict):
                return self._send(400, {"error": "json object required"}, body_text=raw_body)
            qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            obj_key = f"{parsed.path}?role=control" if qs.get("role") == "control" else parsed.path
            op = data.get("op")
            vulnerable = route["vulnerable"]
            with lock:
                obj = biz_objects.get(obj_key)
                if obj is None:
                    return self._send(404, {"error": "missing object"}, body_text=raw_body)
                if route["kind"] == "idempotency_replay" and op == "redeem":
                    if obj["uses"] >= 1 and not vulnerable:
                        return self._send(409, {"error": "single use"}, body_text=raw_body)
                    obj["uses"] += 1
                    obj["total"] -= 10
                    return self._send(200, {"applied": True, "uses": obj["uses"]}, body_text=raw_body)
                if route["kind"] == "sequence_step_skip":
                    if op == "prepare":
                        obj["prepared"] = True
                        return self._send(200, {"applied": True, "prepared": True}, body_text=raw_body)
                    if op == "complete":
                        if not obj["prepared"] and not vulnerable:
                            return self._send(409, {"error": "prepare required"}, body_text=raw_body)
                        obj["status"] = "complete"
                        return self._send(200, {"applied": True, "status": "complete"}, body_text=raw_body)
                if route["kind"] == "schema_symmetry":
                    if op == "title":
                        obj["title"] = str(data.get("title") or "")
                        return self._send(200, {"applied": True, "title": obj["title"]}, body_text=raw_body)
                    if op == "server_tag":
                        if vulnerable:
                            obj["server_tag"] = str(data.get("server_tag") or "")
                        return self._send(200, {"applied": True, "server_tag": obj["server_tag"]}, body_text=raw_body)
            return self._send(400, {"error": "invalid operation"}, body_text=raw_body)

        do_POST = _handle_mutation
        do_PUT = _handle_mutation

        def _deny_other(self):
            return self._send(405, {"error": "method not allowed"})

        do_PATCH = do_DELETE = _deny_other

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def evidence_matches(case: dict, record: dict, wire: list[dict], target: str) -> tuple[str, list[int]]:
    """Verify exact wire + state-transition evidence for SPA XSS and Business Logic cases."""
    if case["class"] == "xss_reflected":
        return readonly_xss_redirect_holdout.evidence_matches(case, record, wire, target)

    origin = urlsplit(target)
    context = record.get("execution_context", {})
    if (
        context.get("vuln_class") != "business_logic"
        or context.get("method") != case["method"]
        or context.get("carrier") != case["carrier"]
    ):
        return "Business logic request context mismatch", []
    if record.get("oracle") != "business_logic":
        return "Business logic holdout requires business_logic oracle", []

    roles: dict[str, dict] = {}
    sequences: list[int] = []
    used_sequences: set[int] = set()
    for response in record.get("request_evidence", []):
        url = urlsplit(response.get("request_url", ""))
        matches = [
            row
            for row in wire
            if row["method"] == response.get("method")
            and row["path"] == case["path"] == url.path
            and row["status"] == response.get("status")
            and row["response_length"] == response.get("response_length")
            and row["response_sha256"] == response.get("response_sha256")
            and hashlib.sha256(str(row["response"]).encode("utf-8")).hexdigest() == row["response_sha256"]
            and len(str(row["response"]).encode("utf-8")) == row["response_length"]
        ]
        if (
            not response.get("transport_ok")
            or not matches
            or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)
        ):
            return "Business logic HTTP evidence does not match exact evaluator wire", []
        unused = [m for m in matches if m["sequence"] not in used_sequences]
        chosen = unused[0] if unused else matches[0]
        used_sequences.add(chosen["sequence"])
        roles[response["role"]] = chosen
        sequences.append(chosen["sequence"])

    required = {
        "control-before", "control-action-0", "control-after",
        "probe-before", "probe-action-0", "probe-after",
    }
    if not required <= roles.keys():
        return "missing stateful business logic control/probe wire steps", []

    evidence = record.get("evidence") or {}
    if evidence.get("normal_control_passed") is not True or evidence.get("kind") != case["kind"]:
        return "normal business control did not pass", []

    try:
        pb = json.loads(roles["probe-before"]["response"])
        pa = json.loads(roles["probe-after"]["response"])
    except (ValueError, TypeError):
        return "invalid JSON state observation on wire", []

    if case["kind"] == "idempotency_replay":
        violated_on_wire = int(pa.get("uses", 0)) >= int(pb.get("uses", 0)) + 2
    elif case["kind"] == "sequence_step_skip":
        violated_on_wire = pb.get("status") == "draft" and pa.get("status") == "complete"
    else:
        violated_on_wire = pb.get("server_tag") != "tampered" and pa.get("server_tag") == "tampered"

    if record.get("verdict") == "CONFIRMED":
        if evidence.get("violation_effect_observed") is not True or not violated_on_wire:
            return "confirmed business logic violation not observed on wire", []
    else:
        if evidence.get("violation_effect_observed") is not False or violated_on_wire:
            return "negative business logic probe unexpectedly mutated protected state", []
    return "", sequences
