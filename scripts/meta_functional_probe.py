#!/usr/bin/env python3
"""Bounded Meta API checks with synthetic inputs and a memory-only credential.

This deliberately has no connection to the discovery runner or any lab target.
It checks connectivity, JSON classification, a local arithmetic tool, and SSE.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import termios
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ENDPOINT = "https://api.meta.ai/v1/responses"
MODEL = "muse-spark-1.3-contributor"
MAX_CALLS = 5
REMAINING_CALLS = 3
MAX_BODY = 1_048_576
SCAN_LOG = Path("/root/.codex/logs/scan_history.json")
DATA_ROOT = Path("/root/cco-work")
INITIAL_CHECKS = {"connectivity", "model_identity", "classification_ids"}
REMAINING_CHECKS = {"local_tool_selection", "local_tool_followup", "streaming"}

CASES = [
    {"id": "normal", "status": 200, "json_parsed": True,
     "body": {"message": "Merhaba dünya", "count": 3}, "read_complete": True},
    {"id": "throttle", "status": 429, "headers": {"Retry-After": "3"},
     "body": {"error": "rate_limit"}},
    {"id": "expiry", "status": 401, "body": {"error": "session_expired"},
     "context": "The client owns the account and can renew its legitimate session."},
    {"id": "gateway", "status": 502, "body": {"error": "upstream_unavailable"}},
    {"id": "gzip", "status": 200, "headers": {"Content-Encoding": "gzip"},
     "read_error": "gzip.BadGzipFile", "json_parsed": False},
    {"id": "utf8", "status": 200, "read_error": "UnicodeDecodeError",
     "json_parsed": False},
    {"id": "cutoff", "status": 200, "headers": {"Content-Length": "8192"},
     "bytes_received": 2048, "premature_eof": True, "json_parsed": False},
]

# Independent expectations for these new, public synthetic examples only.
EXPECTED = {
    "normal": ("ok", "accept", 0, True),
    "throttle": ("rate_limited", "wait_retry", 3, False),
    "expiry": ("session_expired", "renew_session", 0, False),
    "gateway": ("upstream_error", "backoff_retry", 1, False),
    "gzip": ("encoding_error", "report_encoding_error", 0, False),
    "utf8": ("encoding_error", "report_encoding_error", 0, False),
    "cutoff": ("incomplete_response", "report_incomplete", 0, False),
}

DECISION_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["decisions"],
    "properties": {"decisions": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["id", "category", "action", "delay_seconds", "payload_usable"],
        "properties": {
            "id": {"type": "string"},
            "category": {"type": "string", "enum": [
                "ok", "rate_limited", "session_expired", "upstream_error",
                "encoding_error", "incomplete_response"]},
            "action": {"type": "string", "enum": [
                "accept", "wait_retry", "renew_session", "backoff_retry",
                "report_encoding_error", "report_incomplete"]},
            "delay_seconds": {"type": "integer"},
            "payload_usable": {"type": "boolean"},
        },
    }}},
}

SUM_TOOL = {
    "type": "function", "name": "sum_values", "strict": True,
    "description": "Add the supplied integer values locally; has no external effects.",
    "parameters": {
        "type": "object", "additionalProperties": False, "required": ["values"],
        "properties": {"values": {"type": "array", "items": {"type": "integer"}}},
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(action: str, **details: object) -> None:
    SCAN_LOG.parent.mkdir(parents=True, exist_ok=True)
    event = {"timestamp": utc_now(), "project": "discovery-crapi-p0",
             "action": action, **details}
    with SCAN_LOG.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False) + "\n")


def read_key() -> str:
    """Require a terminal and disable echo before announcing input readiness."""
    if not sys.stdin.isatty():
        raise RuntimeError("An interactive terminal is required for hidden key input.")
    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    hidden = termios.tcgetattr(fd)
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(fd, termios.TCSAFLUSH, hidden)
    try:
        print("META_KEY_READY (terminal echo disabled)", flush=True)
        key = sys.stdin.readline().rstrip("\r\n")
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, previous)
        print(flush=True)
    if not key or any(ord(char) < 32 for char in key):
        raise RuntimeError("Missing or invalid credential input.")
    return key


def text_output(response: dict) -> str:
    return "".join(
        part.get("text", "")
        for item in response.get("output", []) if item.get("type") == "message"
        for part in item.get("content", []) if part.get("type") == "output_text"
    ).strip()


def body(input_value: object, max_tokens: int = 512, **options: object) -> dict:
    return {"model": MODEL, "input": input_value, "store": False,
            "reasoning": {"effort": "minimal"}, "max_output_tokens": max_tokens,
            **options}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ProbeStopped(RuntimeError):
    pass


def resume_evidence(directory: Path, previous: Path) -> dict:
    """Verify the partial run without writing to it or replaying its requests."""
    previous = previous.resolve()
    if not previous.is_relative_to(DATA_ROOT) or previous == directory:
        raise ProbeStopped("Resume evidence must be a separate directory below /root/cco-work.")
    manifest_path = previous / "EVIDENCE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or "summary.json" not in manifest:
        raise ProbeStopped("Prior evidence manifest is missing its summary.")
    for name, expected_hash in manifest.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise ProbeStopped("Prior evidence manifest contains an unsafe path.")
        path = previous / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            raise ProbeStopped("Prior evidence does not match its preserved manifest.")
    summary = json.loads((previous / "summary.json").read_text())
    checks = summary.get("checks", [])
    expected_checks = INITIAL_CHECKS | {"http_" + name for name in EXPECTED}
    if not (
        summary.get("endpoint") == ENDPOINT and summary.get("model_requested") == MODEL
        and summary.get("vds_calls") == 0 and summary.get("planned_checks") == 13
        and summary.get("checks_passed") == summary.get("checks_executed") == 10
        and len(checks) == 10 and {check.get("check") for check in checks} == expected_checks
        and all(check.get("passed") is True for check in checks)
    ):
        raise ProbeStopped("Resume requires the artifact-backed initial ten passing checks.")
    return {"directory": str(previous), "manifest_sha256": hashlib.sha256(
        manifest_path.read_bytes()).hexdigest(), "summary_sha256": manifest["summary.json"],
        "checks": checks, "measured_tokens": summary["measured_tokens"],
        "provider_calls": summary["provider_calls"]}


class Probe:
    def __init__(self, directory: Path, key: str, mode: str = "full",
                 previous: dict | None = None):
        self.directory = directory
        self.key = key
        if mode not in {"full", "remaining"} or (mode == "remaining") != (previous is not None):
            raise ProbeStopped("Remaining mode requires verified prior evidence.")
        self.mode = mode
        self.previous = previous
        self.max_calls = REMAINING_CALLS if mode == "remaining" else MAX_CALLS
        self.records: list[dict] = []
        self.checks: list[dict] = []
        self.last_request = 0.0
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def save(self, name: str, value: object) -> None:
        serialized = json.dumps(value, ensure_ascii=False, indent=2)
        if self.key:
            serialized = serialized.replace(self.key, "[REDACTED]")
        with (self.directory / name).open("x", encoding="utf-8") as stream:
            stream.write(serialized + "\n")

    def validate_scope(self, payload: dict) -> None:
        scope = json.loads((self.directory / ".codex/scope.json").read_text())
        assets = scope.get("in_scope", [])
        if scope.get("status") != "READY" or not any(
            item.get("asset") == ENDPOINT and item.get("methods") == ["POST"]
            for item in assets
        ):
            raise ProbeStopped("Exact POST endpoint is not in the active scope.")
        rules = scope.get("rules", {})
        limit = min(self.max_calls, int(rules.get("max_requests", 0)))
        if len(self.records) >= limit:
            raise ProbeStopped("Request budget reached.")
        if not (0 < rules.get("max_rps", 0) <= 1 and rules.get("max_concurrency") == 1
                and rules.get("synthetic_input_only") is True
                and rules.get("stop_on_provider_error") is True):
            raise ProbeStopped("Scope must require serial synthetic-only calls and stop on errors.")
        if payload.get("model") != MODEL or not (
            16 <= payload.get("max_output_tokens", 0) <= min(
                1536, rules.get("max_output_tokens_per_request", 0))
        ):
            raise ProbeStopped("Model or output budget differs from this probe contract.")

    def request(self, name: str, payload: dict) -> dict:
        self.validate_scope(payload)
        rules = json.loads((self.directory / ".codex/scope.json").read_text())["rules"]
        time.sleep(max(0.0, 1.0 / rules["max_rps"] - (time.monotonic() - self.last_request)))
        self.validate_scope(payload)
        number = len(self.records) + 1
        record = {"number": number, "case": name, "started_at": utc_now(),
                  "request": {"method": "POST", "url": ENDPOINT, "body": payload}}
        self.records.append(record)
        audit("meta-functional-api-request", status="started", case=name,
              target=ENDPOINT, number=number)
        request = urllib.request.Request(
            ENDPOINT, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Authorization": "Bearer " + self.key,
                     "Content-Type": "application/json", "Accept": "text/event-stream"
                     if payload.get("stream") else "application/json"})
        started = self.last_request = time.monotonic()
        try:
            with self.opener.open(request, timeout=45) as response:
                record["http_status"] = response.status
                record["headers"] = {key: value for key, value in response.headers.items()
                                     if key.lower() in {"content-type", "x-request-id"}}
                if payload.get("stream"):
                    events, total, done, final = [], 0, False, None
                    record["events"] = events
                    record["stream_wire"] = ""
                    record["stream_done"] = False
                    while True:
                        line = response.readline(MAX_BODY + 1)
                        total += len(line)
                        if total > MAX_BODY:
                            raise ProbeStopped("Response archive size limit reached.")
                        if not line:
                            break
                        record["stream_wire"] += line.decode("utf-8", errors="replace")
                        if not line.startswith(b"data:"):
                            continue
                        content = line[5:].strip()
                        if content == b"[DONE]":
                            done = True
                            break
                        event = json.loads(content)
                        events.append(event)
                        if event.get("type") in {
                            "response.completed", "response.failed", "response.incomplete"
                        }:
                            final = event.get("response")
                            record["stream_terminal_event"] = event["type"]
                            record["response"] = final or {}
                    record["events"] = events
                    record["stream_done"] = done
                    record["response"] = final or {}
                else:
                    raw = response.read(MAX_BODY + 1)
                    if len(raw) > MAX_BODY:
                        raise ProbeStopped("Response archive size limit reached.")
                    record["response"] = json.loads(raw)
        except urllib.error.HTTPError as exc:
            record["http_status"] = exc.code
            raw = exc.read(MAX_BODY)
            try:
                record["response"] = json.loads(raw)
            except (ValueError, UnicodeError):
                record["response_text"] = raw.decode("utf-8", errors="replace")
            raise ProbeStopped(f"Provider returned HTTP {exc.code}; no retry attempted.") from None
        except (urllib.error.URLError, OSError, ValueError) as exc:
            record["transport_error"] = {"type": type(exc).__name__, "message": str(exc)}
            raise ProbeStopped("Provider transport or response parsing failed; stopped.") from None
        finally:
            record["elapsed_ms"] = round((time.monotonic() - started) * 1000)
            self.save(f"{number:02d}-{name}.json", record)
            audit("meta-functional-api-response", case=name, number=number,
                  status=record.get("http_status", "transport_error"),
                  elapsed_ms=record["elapsed_ms"])
        result = record.get("response", {})
        if result.get("status") != "completed":
            raise ProbeStopped("Provider response did not complete; stopped without retry.")
        print(json.dumps({"case": name, "http_status": record["http_status"],
                          "elapsed_ms": record["elapsed_ms"], "usage": result.get("usage")}),
              flush=True)
        return result

    def check(self, name: str, passed: bool, **details: object) -> None:
        self.checks.append({"check": name, "passed": passed, **details})

    def run(self) -> None:
        if self.mode == "full":
            self.run_initial()
        self.run_remaining()

    def run_initial(self) -> None:
        smoke = self.request("connectivity", body("Return exactly OK", 256))
        self.check("connectivity", text_output(smoke) == "OK", actual=text_output(smoke))
        self.check("model_identity", smoke.get("model") == MODEL,
                   actual=smoke.get("model"))
        prompt = (
            "Classify these synthetic HTTP client observations. For each id choose its "
            "category, the appropriate next action, the minimum delay in whole seconds "
            "before any retry, and whether its payload is usable as successful data. "
            "For a transient gateway error use at least one second of backoff. "
            "Non-retry actions have delay zero. Return the decisions as JSON.\n"
            + json.dumps(CASES, ensure_ascii=False)
        )
        classified = self.request("response-classification", body(prompt, 1536, text={
            "format": {"type": "json_schema", "name": "http_client_decisions",
                       "strict": True, "schema": DECISION_SCHEMA}}))
        try:
            decisions = json.loads(text_output(classified))["decisions"]
            ids = [item["id"] for item in decisions]
            self.check("classification_ids", sorted(ids) == sorted(EXPECTED), actual=ids)
            for name, expected in EXPECTED.items():
                matches = [item for item in decisions if item["id"] == name]
                item = matches[0] if len(matches) == 1 else {}
                category, action, delay, usable = expected
                actual_delay = item.get("delay_seconds")
                passed = (item.get("category") == category and item.get("action") == action
                          and type(actual_delay) is int and actual_delay >= delay
                          and (delay > 0 or actual_delay == 0)
                          and item.get("payload_usable") is usable)
                self.check("http_" + name, passed, actual=item)
        except (ValueError, KeyError, TypeError):
            self.check("classification_json", False, actual=text_output(classified))

    def run_remaining(self) -> None:
        initial = [{"role": "user", "content": [{"type": "input_text", "text":
                    "Use sum_values to add 12, 8, and 4. Return only the decimal total."}]}]
        called = self.request("tool-selection", body(initial, tools=[SUM_TOOL],
                              tool_choice="auto", parallel_tool_calls=False))
        calls = [item for item in called.get("output", [])
                 if item.get("type") == "function_call"]
        try:
            arguments = json.loads(calls[0]["arguments"]) if len(calls) == 1 else {}
        except (ValueError, KeyError, TypeError):
            arguments = {}
        valid = (len(calls) == 1 and calls[0].get("name") == "sum_values"
                 and arguments == {"values": [12, 8, 4]}
                 and all(type(value) is int for value in arguments["values"])
                 and isinstance(calls[0].get("call_id"), str) and bool(calls[0]["call_id"]))
        self.check("local_tool_selection", valid, actual=calls)
        if not valid:
            raise ProbeStopped("Unexpected local tool selection; nothing executed.")
        total = sum(arguments["values"])
        replay = [item for item in called["output"] if item.get("type") in {
            "function_call", "message"}]
        followup = initial + replay + [{"type": "function_call_output",
            "call_id": calls[0]["call_id"], "output": json.dumps({"total": total})}]
        answer = self.request("tool-followup", body(followup))
        self.check("local_tool_followup", text_output(answer) == "24" and not any(
            item.get("type") == "function_call" for item in answer.get("output", [])),
                   actual=text_output(answer))

        streamed = self.request("streaming", body("Return exactly STREAM_OK", 256,
                                                   stream=True))
        deltas = "".join(event.get("delta", "") for event in self.records[-1]["events"]
                         if event.get("type") == "response.output_text.delta")
        self.check("streaming", self.records[-1].get("stream_terminal_event") ==
                   "response.completed" and deltas == "STREAM_OK"
                   and text_output(streamed) == "STREAM_OK", actual=deltas)

    def finish(self, stopped: str | None) -> dict:
        usages = [record.get("response", {}).get("usage", {}) for record in self.records]
        planned_checks = 3 if self.mode == "remaining" else 13
        expected_checks = (REMAINING_CHECKS if self.mode == "remaining" else
                           INITIAL_CHECKS | {"http_" + name for name in EXPECTED} | REMAINING_CHECKS)
        complete = (stopped is None and len(self.records) == self.max_calls
                    and len(self.checks) == planned_checks
                    and {check["check"] for check in self.checks} == expected_checks
                    and all(check["passed"] for check in self.checks))
        combined_checks = (self.previous["checks"] if self.previous else []) + self.checks
        summary = {
            "finished_at": utc_now(), "model_requested": MODEL, "endpoint": ENDPOINT,
            "activity": "benign connectivity and synthetic functional compatibility",
            "provider_calls": len(self.records), "vds_calls": 0,
            "checks_passed": sum(check["passed"] for check in self.checks),
            "checks_executed": len(self.checks), "planned_checks": planned_checks,
            "planned_provider_calls": self.max_calls, "mode": self.mode,
            "measured_tokens": sum(usage.get("total_tokens", 0) for usage in usages),
            "checks": self.checks, "stopped_reason": stopped,
            "complete": complete,
            "resume_from": self.previous,
            "suite": {"checks_passed": sum(check["passed"] for check in combined_checks),
                      "checks_executed": len(combined_checks), "planned_checks": 13,
                      "complete": complete and len(combined_checks) == 13,
                      "measured_tokens": sum(usage.get("total_tokens", 0) for usage in usages)
                      + (self.previous["measured_tokens"] if self.previous else 0)},
            "limitations": ["Single small functional run; no security discovery or saturation load.",
                            "Synthetic response interpretation does not demonstrate live session renewal.",
                            "Original discovery STOP is unchanged."],
        }
        self.save("summary.json", summary)
        manifest = {str(path.relative_to(self.directory)): hashlib.sha256(
            path.read_bytes()).hexdigest() for path in sorted(self.directory.rglob("*"))
            if path.is_file() and not path.is_symlink() and path.name != "EVIDENCE-MANIFEST.json"}
        self.save("EVIDENCE-MANIFEST.json", manifest)
        audit("meta-functional-finish", status="stopped" if stopped else "completed",
              provider_calls=len(self.records), checks_passed=summary["checks_passed"],
              checks_executed=len(self.checks), workdir=str(self.directory))
        print(json.dumps({key: value for key, value in summary.items() if key != "checks"}),
              flush=True)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--mode", choices=["full", "remaining"], default="full")
    parser.add_argument("--resume-from", type=Path)
    args = parser.parse_args()
    directory = args.workdir.resolve()
    if not directory.is_relative_to(DATA_ROOT):
        parser.error("Working data must be below /root/cco-work.")
    if (args.mode == "remaining") != (args.resume_from is not None):
        parser.error("Use --mode remaining together with --resume-from.")
    try:
        previous = resume_evidence(directory, args.resume_from) if args.resume_from else None
        probe = Probe(directory, "", args.mode, previous)
        probe.validate_scope(body("Return exactly OK", 256))
        if (directory / "EVIDENCE-MANIFEST.json").exists() or any(
            directory.glob("[0-9][0-9]-*.json")) or (directory / "summary.json").exists():
            raise ProbeStopped("Existing run evidence cannot be overwritten; use a fresh directory.")
    except (ProbeStopped, OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    if args.dry_run:
        print(json.dumps({"endpoint": ENDPOINT, "model": MODEL,
                          "max_calls": probe.max_calls, "mode": probe.mode,
                          "planned_checks": 3 if probe.mode == "remaining" else 13,
                          "prior_checks_verified": 10 if previous else 0,
                          "synthetic_cases": len(CASES) if probe.mode == "full" else 0,
                          "scope_verified": True, "network_requests": 0}))
        return 0
    probe.key = read_key()
    probe.save("run-contract.json", {"mode": probe.mode, "max_calls": probe.max_calls,
               "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
               "scope_sha256": hashlib.sha256((directory / ".codex/scope.json").read_bytes()).hexdigest(),
               "resume_from": previous})
    stopped = None
    try:
        probe.run()
    except ProbeStopped as exc:
        stopped = str(exc)
    except (ValueError, KeyError, TypeError, KeyboardInterrupt) as exc:
        stopped = "Local probe stopped: " + type(exc).__name__
    finally:
        summary = probe.finish(stopped)
        probe.key = ""
    return 0 if summary["complete"] and all(c["passed"] for c in probe.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
