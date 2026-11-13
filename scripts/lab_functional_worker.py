#!/usr/bin/env python3
"""Fixed-operation, temporary SSH worker for the owned functional lab."""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path("/root/crapi-lab")
ORIGIN = "http://127.0.0.1:18901"
MAX_CALLS = 39  # Reserve one of the engagement's 40 calls for the prior inspection.
HARD_CALL_CAP = 125
MAX_BODY = 65536
LARGE_BODY = 3_000_000
PATHS = {
    "session": ("GET", "/api/v1/access/session"),
    "refresh": ("POST", "/api/v1/access/refresh"),
    "gzip": ("GET", "/api/v1/equipment/catalog/export?target_bytes=4096&flavor=gzip-mismatch"),
    "utf8": ("GET", "/api/v1/equipment/catalog/export?target_bytes=4096&flavor=bad-utf8"),
    "cutoff": ("GET", "/api/v1/telemetry/stream?events=100"),
    "health": ("GET", "/proxy/health"),
    "metrics": ("GET", "/proxy/metrics"),
    "large_js": ("GET", "/static/catalog-large.js"),
    "large_json": ("GET", "/api/v1/equipment/catalog/export?target_bytes=2097152&nesting_depth=20&evidence_position=end"),
    "challenge": ("GET", "/api/v1/telemetry/overview"),
    "challenge_solved": ("GET", "/api/v1/telemetry/overview"),
    "cutoff_solved": ("GET", "/api/v1/telemetry/stream?events=100"),
}
PROFILES = {
    "session": {"ttl": 25, "every502": 0, "rate": 0, "cut": 0},
    "cutoff": {"ttl": 3600, "every502": 0, "rate": 0, "cut": 2048},
    "gateway": {"ttl": 3600, "every502": 3, "rate": 0, "cut": 0},
    "throttle": {"ttl": 3600, "every502": 0, "rate": 3, "cut": 0},
    "large": {"ttl": 3600, "every502": 0, "rate": 0, "cut": 0},
    "network": {"ttl": 3600, "every500": 17, "every502": 23, "rate": 40,
                "cut": 0, "delay": 300, "challenge": "/api/v1/telemetry", "max_requests": 600},
    "combined": {"ttl": 3600, "every500": 17, "every502": 23, "rate": 40,
                 "cut": 2048, "delay": 300, "challenge": "/api/v1/telemetry", "max_requests": 120},
    "budget": {"ttl": 3600, "every502": 0, "rate": 0, "cut": 2048, "max_requests": 120},
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Worker:
    def __init__(self, name: str, max_calls: int = MAX_CALLS):
        if not re.fullmatch(r"functional-[0-9]{8}T[0-9]{6}Z", name):
            raise ValueError("Invalid isolated functional run name.")
        self.name = name
        if not 1 <= max_calls <= HARD_CALL_CAP:
            raise ValueError("Invalid worker request budget.")
        self.max_calls = max_calls
        self.run = ROOT / "runs" / name
        self.original = ROOT / "runs/run-p0-01"
        self.token = ""
        self.csrf = ""
        self.secrets = set()
        self.account = None
        self.calls = 0
        self.last = 0.0
        self.prepared = False
        self.restored = False
        self.phase = "preflight"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def redact(self, value):
        serialized = json.dumps(value, ensure_ascii=False)
        for secret in sorted(self.secrets, key=len, reverse=True):
            if secret:
                serialized = serialized.replace(secret, "[REDACTED]")
        return json.loads(serialized)

    def request(self, case: str):
        if self.calls >= self.max_calls:
            raise RuntimeError("Lab request budget reached.")
        if case == "login":
            if not self.account:
                raise RuntimeError("No isolated synthetic account loaded.")
            method, path = "POST", "/api/v1/access/sign-in"
            payload = {"work_email": self.account["work_email"], "password": self.account["password"]}
        else:
            method, path = PATHS[case]
            payload = None
        time.sleep(max(0.0, 0.6 - (time.monotonic() - self.last)))
        self.calls += 1
        started = self.last = time.monotonic()
        headers = {"Accept": "application/json"}
        if self.token and case not in {"login", "health", "metrics"}:
            headers["Authorization"] = "Bearer " + self.token
        if case in {"challenge_solved", "cutoff_solved"}:
            headers["X-Challenge-Solved"] = "yes"
        data = json.dumps(payload).encode() if payload is not None else None
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(ORIGIN + path, data=data, method=method, headers=headers)
        raw, transport_error = b"", None
        try:
            response = self.opener.open(request, timeout=12)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            status = response.code
            received_headers = {key.lower(): value for key, value in response.headers.items()}
            try:
                body_limit = LARGE_BODY if case in {"large_js", "large_json"} else MAX_BODY
                raw = response.read(body_limit + 1)
            except http.client.IncompleteRead as exc:
                raw = exc.partial
                transport_error = "IncompleteRead"
        if len(raw) > body_limit:
            raise RuntimeError("Functional response size budget reached.")
        if 300 <= status < 400:
            raise RuntimeError("Lab redirect refused.")
        parsed = None
        try:
            parsed = json.loads(raw)
        except (ValueError, UnicodeError):
            pass
        old_token, old_csrf = self.token, self.csrf
        token_changed, csrf_rotated = None, None
        if case == "login" and status == 200 and isinstance(parsed, dict):
            self.token, self.csrf = parsed["access_token"], parsed["csrf_token"]
            self.secrets.update([self.token, self.csrf])
            token_changed = bool(old_token) and self.token != old_token
            csrf_rotated = bool(old_csrf) and self.csrf != old_csrf
        if case == "refresh" and status == 200 and isinstance(parsed, dict):
            self.csrf = parsed["csrf_token"]
            self.secrets.add(self.csrf)
            csrf_rotated = self.csrf != old_csrf
        decode_error = transport_error
        if received_headers.get("content-encoding") == "gzip":
            try:
                gzip.decompress(raw)
            except (OSError, EOFError):
                decode_error = "gzip.BadGzipFile"
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            decode_error = "UnicodeDecodeError"
        normalized = {"status": status, "json_parsed": parsed is not None and decode_error is None}
        stop_reason = None
        normalized["headers"] = {key: value for key, value in received_headers.items()
                                 if key in {"retry-after", "content-encoding", "x-lab-stream-cut", "x-challenge"}}
        if decode_error:
            normalized["read_error"] = decode_error
        if isinstance(parsed, dict) and parsed.get("error") == "session_expired":
            normalized["body"] = {"error": "session_expired"}
            normalized["context"] = "The client owns the account and may renew its legitimate session."
        if status in {500, 502}:
            if received_headers.get("x-lab-injected") != str(status):
                stop_reason = "Unexpected upstream failure; stop on service degradation."
            normalized["body"] = {"error": "upstream_unavailable"}
        if status >= 500 and status not in {500, 502}:
            stop_reason = "Unexpected service degradation."
        if case in {"cutoff", "cutoff_solved"}:
            completed = 0
            for line in raw.splitlines():
                try:
                    json.loads(line)
                    completed += 1
                except (ValueError, UnicodeError):
                    pass
            normalized.update(bytes_received=len(raw), expected_events=100,
                              completed_events=completed, stream_incomplete=completed != 100,
                              read_complete=transport_error is None)
        if case in {"large_js", "large_json"}:
            normalized.update(bytes_received=len(raw), read_complete=transport_error is None,
                              utf8_decoded=decode_error != "UnicodeDecodeError")
            if case == "large_json" and isinstance(parsed, dict):
                def depth(value):
                    if isinstance(value, dict):
                        return 1 + max((depth(item) for item in value.values()), default=0)
                    if isinstance(value, list):
                        return 1 + max((depth(item) for item in value), default=0)
                    return 0
                normalized["nesting_depth"] = depth(parsed)
                normalized["tail_marker_present"] = str(parsed.get("tail_evidence", "")).startswith("CATALOG-EVIDENCE")
        record = {"number": self.calls, "phase": self.phase, "case": case,
                  "method": method, "path": path, "status": status,
                  "started_monotonic": started, "elapsed_seconds": time.monotonic() - started,
                  "headers": {key: value for key, value in received_headers.items()
                              if key in {"content-type", "content-length", "content-encoding",
                                         "retry-after", "x-lab-injected", "x-lab-stream-cut", "x-challenge"}},
                  "raw_body_sha256": hashlib.sha256(raw).hexdigest(),
                  "body_redacted": raw.decode("utf-8", errors="replace"),
                  "bytes_received": len(raw), "decode_error": decode_error,
                  "token_changed": token_changed, "csrf_rotated": csrf_rotated,
                  "own_account": parsed.get("alias") == "tech-north-a" if isinstance(parsed, dict) else None,
                  "normalized": normalized}
        if stop_reason:
            record["stop_reason"] = stop_reason
        record = self.redact(record)
        if self.run.is_dir():
            with (self.run / "functional-exchanges.jsonl").open("a") as stream:
                stream.write(json.dumps(record) + "\n")
        if stop_reason:
            raise RuntimeError(stop_reason)
        return record

    def configure(self, phase: str):
        settings = PROFILES[phase]
        if not self.prepared:
            active = ROOT / "runs/active"
            if not active.is_symlink() or active.resolve() != self.original or self.run.exists():
                raise RuntimeError("Safe isolated run setup refused.")
            health = self.request("health")
            if health["status"] != 200 or json.loads(health["body_redacted"]).get("profile") != "normal":
                raise RuntimeError("Original lab must be healthy and normal before changes.")
            self.prepared = True
            subprocess.run([str(ROOT / "lab.sh"), "prepare", self.name, "--seed", self.name],
                           cwd=ROOT, check=True, capture_output=True, timeout=20)
            accounts = json.loads((self.run / "agent-credentials.json").read_text())["test_accounts"]
            self.account = next(account for account in accounts if account["alias"] == "tech-north-a")
            self.secrets.update([self.account["work_email"], self.account["password"]])
        self.phase = phase
        environment = {"LAB_PROFILE": "functional-" + phase,
                       "MAX_REQUESTS": str(settings.get("max_requests", 40)),
                       "STRESS_DELAY_MS": str(settings.get("delay", 0)),
                       "STRESS_EVERY_N_500": str(settings.get("every500", 0)),
                       "STRESS_EVERY_N_502": str(settings["every502"]),
                       "STRESS_RATE_LIMIT_PER_MIN": str(settings["rate"]),
                       "STRESS_CHALLENGE_PREFIXES": settings.get("challenge", ""),
                       "STRESS_CUT_STREAM_AFTER_BYTES": str(settings["cut"])}
        override = {"services": {"lab-app": {"environment": {
            "SESSION_TTL_SECONDS": str(settings["ttl"])}}, "lab-proxy": {"environment": environment}}}
        path = self.run / ("functional-" + phase + ".json")
        with path.open("x") as stream:
            json.dump(override, stream)
        command = ["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
                   "-f", str(path), "up", "-d", "--no-build", "--force-recreate",
                   "--wait", "--wait-timeout", "40"]
        subprocess.run(command, cwd=ROOT, env={**os.environ, "RUN_ID": self.name},
                       check=True, capture_output=True, timeout=60)
        self.token, self.csrf = "", ""
        health = self.request("health")
        parsed = json.loads(health["body_redacted"])
        if parsed.get("run_id") != self.name or parsed.get("profile") != "functional-" + phase:
            raise RuntimeError("Isolated functional profile did not become healthy.")
        return {"configured": phase, "settings": settings, "health": health}

    def restore(self):
        if not self.prepared or self.restored:
            return {"restored": self.restored, "calls": self.calls}
        active = ROOT / "runs/active"
        if not active.is_symlink() or active.resolve() != self.run or not self.original.is_dir():
            raise RuntimeError("Original run restore refused due to unexpected active state.")
        active.unlink()
        active.symlink_to(self.original)
        subprocess.run(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
                        "up", "-d", "--no-build", "--force-recreate", "--wait", "--wait-timeout", "40"],
                       cwd=ROOT, env={**os.environ, "RUN_ID": "run-p0-01"},
                       check=True, capture_output=True, timeout=60)
        self.phase = "restored"
        health = self.request("health")
        parsed = json.loads(health["body_redacted"])
        self.restored = parsed.get("run_id") == "run-p0-01" and parsed.get("profile") == "normal"
        return {"restored": self.restored, "health": health, "calls": self.calls}

    def dispatch(self, action):
        operation = action["action"]
        if operation == "configure":
            return self.configure(action["phase"])
        if operation == "request":
            return self.request(action["case"])
        if operation == "wait":
            seconds = action["seconds"]
            if type(seconds) not in {int, float} or not 0 <= seconds <= 61:
                raise ValueError("Wait budget refused.")
            started = time.monotonic()
            time.sleep(seconds)
            return {"waited_seconds": time.monotonic() - started}
        if operation == "snapshot":
            record = self.request("metrics")
            with (self.run / ("functional-metrics-" + self.phase + ".json")).open("x") as stream:
                json.dump(record, stream)
            return record
        if operation == "trace":
            path = self.run / "proxy.log"
            raw = path.read_bytes()
            if len(raw) > 1_048_576:
                raise RuntimeError("Proxy trace size limit reached.")
            text = raw.decode("utf-8", errors="replace")
            # Keep the original bytes' digest and text even when framing is malformed.
            events = []
            decoder = json.JSONDecoder()
            remainder = text
            parse_errors = 0
            while remainder.strip():
                remainder = remainder.lstrip()
                if remainder.startswith("\\n"):
                    remainder = remainder[2:]
                    continue
                try:
                    event, consumed = decoder.raw_decode(remainder)
                    events.append(event)
                    remainder = remainder[consumed:]
                except ValueError:
                    parts = remainder.split("\n", 1)
                    match = re.match(r"^\[(.*?)\] \[SEQ=(\d+)\] actor=\S+ (\S+)\s+(.+?)\s+"
                                     r"->\s+(\d+)\s+\(\s*([\d.]+)ms\) FORWARDED=(True|False) evidence_ref=(.*)$",
                                     parts[0])
                    if match:
                        events.append({"timestamp": match[1], "seq": int(match[2]), "method": match[3],
                                       "path": match[4].strip(), "status": int(match[5]),
                                       "duration_ms": float(match[6]), "forwarded": match[7] == "True",
                                       "evidence_ref": match[8]})
                    else:
                        parse_errors += 1
                    remainder = parts[1] if len(parts) == 2 else ""
            return self.redact({"proxy_log_sha256": hashlib.sha256(raw).hexdigest(),
                                "raw_log": text, "events": events, "parse_errors": parse_errors})
        if operation == "restore":
            return self.restore()
        raise ValueError("Unknown fixed worker operation.")


def main():
    worker = Worker(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else MAX_CALLS)
    signal.signal(signal.SIGALRM, lambda *args: (_ for _ in ()).throw(TimeoutError("Worker deadline")))
    signal.alarm(900)
    print(json.dumps({"ready": True}), flush=True)
    try:
        for line in sys.stdin:
            action = json.loads(line)
            if action.get("action") == "close":
                break
            try:
                result = worker.dispatch(action)
            except Exception as exc:
                result = {"error_class": type(exc).__name__, "error": str(exc), "calls": worker.calls}
            print(json.dumps(result), flush=True)
    finally:
        if worker.prepared and not worker.restored:
            try:
                worker.restore()
            except Exception:
                print(json.dumps({"automatic_restore_failed": True}), flush=True)
        worker.secrets.clear()
        worker.account = None
        worker.token = worker.csrf = ""


if __name__ == "__main__":
    main()
