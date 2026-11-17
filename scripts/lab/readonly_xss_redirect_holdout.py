"""Independent ephemeral reflected-XSS (Chromium execution) and Open Redirect GET holdout lab.

Exposes 8 reflected-XSS cases (4 unescaped HTML rendered in Chromium + 4 HTML-escaped/tag-stripped
negatives) and 8 Open Redirect cases (4 unvalidated external Location redirects + 4 allowlisted/fixed
local negatives). Evaluator truth never enters the solver runtime.
"""
from __future__ import annotations

import hashlib
import html
import random
import re
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

FAMILY = "readonly-xss-redirect"
VERSION = "readonly-xss-redirect/1"


def serve(seed: int, port: int = 0):
    if type(seed) is not int or not 0 <= seed < 2**63:
        raise ValueError("holdout seed must be an unsigned 63-bit integer")
    rng = random.Random(seed)
    accounts = {"member-a": {"token": secrets.token_urlsafe(32), "role": "member"}}

    xss_catalogs = ["/xss/" + secrets.token_hex(6) for _ in range(2)]
    redirect_catalogs = ["/go/" + secrets.token_hex(6) for _ in range(2)]
    routes: dict[str, dict] = {}
    truth: list[dict] = []

    xss_modes = [
        "rendered_html", "rendered_html", "rendered_html", "rendered_html",
        "html_escaped", "html_escaped", "tag_stripped", "tag_stripped",
    ]
    rng.shuffle(xss_modes)
    xss_cases: dict[str, list[str]] = {cat: [] for cat in xss_catalogs}
    for idx, mode in enumerate(xss_modes):
        catalog = xss_catalogs[idx % len(xss_catalogs)]
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{catalog}/{identifier}"
        routes[path] = {"class": "xss_reflected", "mode": mode}
        xss_cases[catalog].append(f"{path}?q=hello")
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

    redirect_modes = [
        "unvalidated_redirect", "unvalidated_redirect", "unvalidated_redirect", "unvalidated_redirect",
        "allowlisted_path", "allowlisted_path", "fixed_local_redirect", "fixed_local_redirect",
    ]
    rng.shuffle(redirect_modes)
    redirect_cases: dict[str, list[str]] = {cat: [] for cat in redirect_catalogs}
    for idx, mode in enumerate(redirect_modes):
        catalog = redirect_catalogs[idx % len(redirect_catalogs)]
        identifier = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        path = f"{catalog}/{identifier}"
        routes[path] = {"class": "open_redirect", "mode": mode}
        redirect_cases[catalog].append(f"{path}?next=home")
        truth.append({
            "case": identifier,
            "family": FAMILY,
            "path": path,
            "class": "open_redirect",
            "method": "GET",
            "carrier": "query",
            "param": "next",
            "baseline": "home",
            "expected": "positive" if mode == "unvalidated_redirect" else "negative",
            "negative_behavior": None if mode == "unvalidated_redirect" else mode,
        })

    rng.shuffle(truth)
    lock = threading.Lock()
    state = {
        "accounts": accounts,
        "requests": 0,
        "lock": lock,
        "lab_version": VERSION,
        "truth": truth,
        "wire": [],
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def _send(self, status: int, payload: str, *, content_type: str = "text/html", location: str = "") -> None:
            raw = payload.encode("utf-8")
            with lock:
                state["requests"] += 1
                state["wire"].append({
                    "sequence": state["requests"],
                    "method": self.command,
                    "path": urlsplit(self.path).path,
                    "request_path": self.path,
                    "status": status,
                    "response_length": len(raw),
                    "response_sha256": hashlib.sha256(raw).hexdigest(),
                    "response": payload,
                    "location": location,
                })
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                links = " ".join(
                    f'<a href="{cat}">Browse</a>'
                    for cat in [*xss_catalogs, *redirect_catalogs]
                )
                return self._send(200, f"<html><body>XSS and Redirect Surface member-a {links}</body></html>")
            if parsed.path in xss_cases:
                links = " ".join(f'<a href="{href}">Inspect</a>' for href in xss_cases[parsed.path])
                return self._send(200, f"<html><body>{links}</body></html>")
            if parsed.path in redirect_cases:
                links = " ".join(f'<a href="{href}">Continue</a>' for href in redirect_cases[parsed.path])
                return self._send(200, f"<html><body>{links}</body></html>")
            if parsed.path == "/home":
                return self._send(200, "<html><body>Safe local home member-a</body></html>")
            route = routes.get(parsed.path)
            if not route:
                return self._send(404, "missing endpoint", content_type="text/plain")
            params = parse_qsl(parsed.query, keep_blank_values=True)
            mode = route["mode"]
            if route["class"] == "xss_reflected":
                if len(params) != 1 or params[0][0] != "q" or len(params[0][1]) > 256:
                    return self._send(400, "<html><body>invalid input</body></html>")
                value = params[0][1]
                if mode == "rendered_html":
                    return self._send(200, f"<html><body><div>Search: {value}</div></body></html>")
                if mode == "html_escaped":
                    return self._send(200, f"<html><body><div>Search: {html.escape(value)}</div></body></html>")
                cleaned = re.sub(r"[<>\"']", "", value)
                return self._send(200, f"<html><body><div>Search: {cleaned}</div></body></html>")
            if len(params) != 1 or params[0][0] != "next" or len(params[0][1]) > 256:
                return self._send(400, "invalid input", content_type="text/plain")
            value = params[0][1]
            if value in {"home", "/home"}:
                return self._send(200, "safe local destination /home", content_type="text/plain")
            if mode == "unvalidated_redirect":
                return self._send(302, "redirecting", content_type="text/plain", location=value)
            if mode == "allowlisted_path":
                return self._send(400, "invalid redirect target", content_type="text/plain")
            return self._send(200, "safe local destination /home", content_type="text/plain")

        def _deny_mutation(self):
            return self._send(405, "read-only fixture", content_type="text/plain")

        do_POST = do_PUT = do_PATCH = do_DELETE = _deny_mutation

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.blind_state = state
    return server


def evidence_matches(case: dict, record: dict, wire: list[dict], target: str) -> tuple[str, list[int]]:
    """Exact GET request/response and Chromium execution / Location header gate before metric credit."""
    origin = urlsplit(target)
    context = record.get("execution_context", {})
    if (
        context.get("vuln_class") != case["class"]
        or context.get("param") != case["param"]
        or context.get("method") != "GET"
        or context.get("carrier") != "query"
    ):
        return "XSS/Redirect request context mismatch", []
    roles: dict[str, dict] = {}
    sequences: list[int] = []
    requests: list[dict] = []
    used_sequences: set[int] = set()
    for response in record.get("request_evidence", []):
        url = urlsplit(response.get("request_url", ""))
        matches = [
            row
            for row in wire
            if row["method"] == response.get("method") == "GET"
            and row["path"] == case["path"] == url.path
            and parse_qsl(urlsplit(row["request_path"]).query, keep_blank_values=True)
            == parse_qsl(url.query, keep_blank_values=True)
            and row["status"] == response.get("status")
            and row["response_length"] == response.get("response_length")
            and row["response_sha256"] == response.get("response_sha256")
            and hashlib.sha256(row["response"].encode("utf-8")).hexdigest() == row["response_sha256"]
            and len(row["response"].encode("utf-8")) == row["response_length"]
        ]
        if (
            not response.get("transport_ok")
            or not matches
            or (url.scheme, url.netloc) != (origin.scheme, origin.netloc)
        ):
            return "XSS/Redirect HTTP evidence does not match exact evaluator wire", []
        unused = [m for m in matches if m["sequence"] not in used_sequences]
        chosen = unused[0] if unused else matches[0]
        used_sequences.add(chosen["sequence"])
        roles[response["role"]] = chosen
        sequences.append(chosen["sequence"])
        requests.append(chosen)

    confirmed = record.get("verdict") == "CONFIRMED"
    if case["class"] == "xss_reflected":
        if confirmed:
            if record.get("oracle") != "browser_execution":
                return "XSS holdout confirmation requires browser_execution oracle", []
            required = {
                "reflection-probe",
                "browser-xss-baseline",
                "browser-xss-inert-control",
                "browser-xss-execution-probe",
                "browser-xss-execution-repeat",
            }
            if not required <= roles.keys():
                return "missing XSS browser execution controls", []
            if "baseline" in roles and roles["baseline"]["status"] != 200:
                return "XSS baseline control failed", []
            if "negative-control" in roles and roles["negative-control"]["status"] != 200:
                return "XSS negative control failed", []
            execution = (record.get("evidence") or {}).get("execution") or {}
            observations = execution.get("observations") or []
            if (
                execution.get("completed") is not True
                or execution.get("browser") != "chromium"
                or execution.get("fallback") is not False
                or execution.get("verdict") != "CONFIRMED"
                or len(observations) != 4
                or any(row.get("dialogs_seen") for row in observations[:2])
                or not all((row.get("correlated_alerts") or 0) > 0 for row in observations[2:])
            ):
                return "Chromium XSS execution controls or correlated alerts incomplete", []
            for role in ("browser-xss-execution-probe", "browser-xss-execution-repeat"):
                row = roles[role]
                if row["status"] != 200 or "<svg onload=\"alert('cco-xss-" not in row["response"]:
                    return "unescaped XSS execution payload not observed on wire", []
        else:
            if record.get("oracle") not in {"unescaped_reflection", "browser_execution"}:
                return "unexpected XSS negative oracle", []
            if "reflection-probe" not in roles or len(sequences) < 3:
                return "negative XSS controls incomplete", []
            if any(row["status"] != 200 for row in requests):
                return "negative XSS control status failed", []
            if re.search(r"<cco[0-9a-f]{8}>", roles["reflection-probe"]["response"]):
                return "unescaped canary reflected in negative XSS control", []
        return "", sequences

    if record.get("oracle") != "redirect_location":
        return "Open Redirect holdout requires redirect_location oracle", []
    if confirmed:
        if "redirect-hop-0" not in roles:
            return "missing redirect-hop-0 probe", []
        hop0 = roles["redirect-hop-0"]
        evidence = record.get("evidence") or {}
        sentinel = str(evidence.get("redirect_host") or "").lower()
        hop_loc = str(hop0.get("location") or "")
        if (
            hop0["status"] not in {301, 302, 303, 307, 308}
            or not sentinel.endswith(".cco-validate.test")
            or hop_loc != evidence.get("location_header")
            or sentinel not in hop_loc.lower()
        ):
            return "confirmed Open Redirect Location header does not match sentinel on wire", []
        if "baseline" in roles and (roles["baseline"]["status"] != 200 or roles["baseline"].get("location")):
            return "Open Redirect baseline control failed", []
        if "negative-control" in roles and (
            roles["negative-control"]["status"] != 200 or roles["negative-control"].get("location")
        ):
            return "Open Redirect negative control failed", []
    else:
        if len(sequences) < 5:
            return "negative Open Redirect controls incomplete", []
        if roles.get("baseline", {}).get("status") != 200 or roles.get("negative-control", {}).get("status") != 200:
            return "negative Open Redirect baseline/control failed", []
        if any(row["status"] not in {200, 400, 422} or row.get("location") for row in requests):
            return "negative Open Redirect probe unexpectedly redirected", []
    return "", sequences
