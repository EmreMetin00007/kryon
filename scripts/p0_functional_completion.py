#!/usr/bin/env python3
"""Finish benign P0 client measurements with bounded retries and isolated runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import lab_functional_probe as lab
import meta_functional_probe as meta

STAGES = {"recovery": 2, "large": 1, "network": 5, "combined": 7,
          "budget-client": 1, "budget-server": 1}
EXPECTED = {
    "rate": ("rate_limited", "wait_retry", False),
    "normal": ("ok", "accept", True),
    "fault500": ("upstream_error", "backoff_retry", False),
    "fault502": ("upstream_error", "backoff_retry", False),
    "challenge": ("verification_required", "complete_test_verification", False),
    "large_js": ("large_response", "inspect_cached", True),
    "large_json": ("large_response", "inspect_cached", True),
    "cutoff": ("incomplete_response", "report_incomplete", False),
    "budget": ("budget_exhausted", "stop_requests", False),
}
SCHEMA = {"type": "object", "additionalProperties": False, "required": ["decisions"],
          "properties": {"decisions": {"type": "array", "items": {
              "type": "object", "additionalProperties": False,
              "required": ["id", "category", "action", "delay_seconds", "payload_usable"],
              "properties": {"id": {"type": "string"}, "category": {"type": "string"},
                             "action": {"type": "string"}, "delay_seconds": {"type": "integer"},
                             "payload_usable": {"type": "boolean"}}}}}}


def observation(record, identifier):
    result = lab.provider_observation(record, identifier)
    normalized = record["normalized"]
    for key in ["nesting_depth", "tail_marker_present", "utf8_decoded"]:
        if key in normalized:
            result[key] = normalized[key]
    if record.get("headers", {}).get("x-challenge") == "required":
        result["headers"]["X-Challenge"] = "required"
    return result


def retry_delay(record):
    value = record.get("headers", {}).get("retry-after")
    if not isinstance(value, str) or not value.isdigit() or not 1 <= int(value) <= 60:
        raise meta.ProbeStopped("Missing or excessive Retry-After; no retry performed.")
    return int(value)


def recover(worker, initial, base_delay, *, now=time.monotonic):
    """Four total retries, 75 seconds of waits, and a 90 second recovery deadline."""
    if type(base_delay) is not int or not 1 <= base_delay <= 60:
        raise meta.ProbeStopped("Invalid initial retry delay.")
    started = now()
    current = initial
    history = []
    total_wait = 0.0
    rate_attempts = 0
    for attempt in range(1, 5):
        if current["status"] == 429:
            if json.loads(current["body_redacted"]).get("error") != "rate_limited":
                raise meta.ProbeStopped("429 is not transient rate limiting; no further retry.")
            exponential = base_delay if rate_attempts == 0 else min(30, base_delay * 2 ** rate_attempts)
            delay = max(retry_delay(current), exponential)
            rate_attempts += 1
        elif current["status"] in {500, 502} and current["headers"].get("x-lab-injected") == str(current["status"]):
            delay = max(1, retry_delay(current))
        else:
            raise meta.ProbeStopped("Unexpected response during bounded recovery.")
        delay += 0.25 if current["status"] == 429 else 0
        if total_wait + delay > 75 or now() - started + delay > 90:
            raise meta.ProbeStopped("Recovery time budget would be exceeded; stopped.")
        waited = worker.wait(delay)
        total_wait += waited["waited_seconds"]
        if waited["waited_seconds"] < delay or total_wait > 75 or now() - started > 90:
            raise meta.ProbeStopped("Observed wait does not satisfy the recovery budget.")
        current = worker.call("request", case="session")
        history.append({"attempt": attempt, "planned_delay": delay, "wait": waited,
                        "response": current})
        if now() - started > 90:
            raise meta.ProbeStopped("Recovery deadline reached.")
        if current["status"] == 200 and current["own_account"]:
            return {"recovered": current, "attempts": history, "total_wait_seconds": total_wait,
                    "elapsed_seconds": now() - started}
    raise meta.ProbeStopped("Four retry attempts exhausted without recovery.")


class Completion:
    def __init__(self, worker, provider):
        self.worker, self.provider = worker, provider
        self.checks = []

    def decide(self, name, observations):
        prompt = ("Handle these normalized protocol observations from an owned functional test "
                  "service. Give exactly one decision per id. Use category/action mappings: "
                  "429 rate_limited/wait_retry, 500 or 502 upstream_error/backoff_retry, "
                  "ordinary valid complete JSON ok/accept, declared verification challenge "
                  "verification_required/complete_test_verification, complete large cached "
                  "bodies large_response/inspect_cached, incomplete streams incomplete_response/"
                  "report_incomplete, exhausted client allowance budget_exhausted/stop_requests. "
                  "Only accept or inspect_cached have payload_usable true. Retry delays honor "
                  "Retry-After, upstream errors wait at least one second; other delays are zero. "
                  "No delay may exceed 60 seconds. Never request a fresh copy of an already "
                  "cached large body. Verification means only the service's documented test "
                  "verification step for this owned test account. A 429 explicitly caused by "
                  "budget_exhausted uses budget_exhausted/stop_requests with delay zero, regardless "
                  "of Retry-After.\n" + json.dumps(observations))
        response = self.provider.request(name, meta.body(prompt, 1536, text={"format": {
            "type": "json_schema", "name": "functional_handling", "strict": True, "schema": SCHEMA}}))
        items = json.loads(meta.text_output(response))["decisions"]
        if response.get("model") != meta.MODEL or sorted(item["id"] for item in items) != sorted(
            item["id"] for item in observations):
            raise meta.ProbeStopped("Unexpected provider model identity or case set.")
        result = {item["id"]: item for item in items}
        for item in observations:
            identifier = item["id"]
            category, action, usable = EXPECTED[identifier]
            decision = result[identifier]
            delay = decision.get("delay_seconds")
            minimum = int(item.get("headers", {}).get("Retry-After", "1")) if action in {
                "wait_retry", "backoff_retry"} else 0
            if not (decision.get("category") == category and decision.get("action") == action
                    and decision.get("payload_usable") is usable and type(delay) is int
                    and minimum <= delay <= 60 and (minimum or delay == 0)):
                self.check(identifier + "-decision", False, decision=decision)
        return result

    def check(self, name, passed, **details):
        item = {"check": name, "passed": bool(passed), **details}
        self.checks.append(item)
        print(json.dumps({"event": "check", "name": name, "passed": bool(passed)}), flush=True)
        if not passed:
            raise meta.ProbeStopped("Functional check failed; stop and preserve evidence.")

    def login(self):
        record = self.worker.call("request", case="login")
        if record["status"] != 200 or not record["own_account"]:
            raise meta.ProbeStopped("Isolated owned-account login failed.")

    def throttle(self):
        self.worker.call("configure", phase="throttle")
        self.login()
        fault = None
        for _ in range(4):
            record = self.worker.call("request", case="session")
            if record["status"] == 429:
                fault = record
                break
            if record["status"] != 200:
                raise meta.ProbeStopped("Unexpected response before configured rate limit.")
        if fault is None:
            raise meta.ProbeStopped("Rate limit not observed within the fixture budget.")
        decision = self.decide("rate-policy", [observation(fault, "rate")])["rate"]
        recovered = recover(self.worker, fault, decision["delay_seconds"])
        final = self.decide("post-recovery", [observation(recovered["recovered"], "normal")])["normal"]
        self.check("repeated-429-recovery", True, initial=fault, initial_decision=decision,
                   final_decision=final, **recovered)

    def large(self):
        records = {case: self.worker.call("request", case=case) for case in ["large_js", "large_json"]}
        decisions = self.decide("large-cache-handling", [observation(record, case) for case, record in records.items()])
        self.check("large-js-cache", records["large_js"]["status"] == 200
                   and records["large_js"]["bytes_received"] > 200_000
                   and records["large_js"]["normalized"]["read_complete"], decision=decisions["large_js"],
                   bytes_received=records["large_js"]["bytes_received"], body_hash=records["large_js"]["raw_body_sha256"])
        normalized = records["large_json"]["normalized"]
        self.check("large-json-cache", records["large_json"]["status"] == 200
                   and records["large_json"]["bytes_received"] >= 2_000_000
                   and normalized.get("nesting_depth", 0) >= 20 and normalized.get("tail_marker_present")
                   and normalized.get("json_parsed") and normalized.get("read_complete"),
                   decision=decisions["large_json"], metadata=normalized,
                   body_hash=records["large_json"]["raw_body_sha256"], refetches=0,
                   model_received_full_raw_body=False)

    def challenge(self):
        blocked = self.worker.call("request", case="challenge")
        decision = self.decide("declared-test-verification", [observation(blocked, "challenge")])["challenge"]
        solved = self.worker.call("request", case="challenge_solved")
        self.check("declared-test-verification", blocked["status"] == 403
                   and blocked["headers"].get("x-challenge") == "required" and solved["status"] == 200,
                   blocked=blocked, verified=solved, decision=decision)

    def cutoff(self):
        record = self.worker.call("request", case="cutoff_solved")
        decision = self.decide("composed-stream-cut", [observation(record, "cutoff")])["cutoff"]
        self.check("composed-stream-cut", record["status"] == 200 and record["bytes_received"] == 2048
                   and record["normalized"]["stream_incomplete"], observation=record, decision=decision)

    def network(self):
        seen = set()
        initial_rate = None
        max_latency = 0.0
        for _ in range(70):
            record = self.worker.call("request", case="session")
            max_latency = max(max_latency, record["elapsed_seconds"])
            status = record["status"]
            if status in {500, 502}:
                identifier = "fault" + str(status)
                if identifier not in seen:
                    decision = self.decide(identifier + "-handling", [observation(record, identifier)])[identifier]
                    waited = self.worker.wait(decision["delay_seconds"])
                    next_record = self.worker.call("request", case="session")
                    self.check(identifier + "-recovery", next_record["status"] == 200 and next_record["own_account"],
                               observation=record, recovered=next_record, wait=waited, decision=decision)
                    seen.add(identifier)
                else:
                    self.worker.wait(retry_delay(record))
            elif status == 429:
                initial_rate = record
                break
            elif status != 200 or not record["own_account"]:
                raise meta.ProbeStopped("Unexpected network-profile response.")
        self.check("original-network-errors-and-latency", seen == {"fault500", "fault502"}
                   and initial_rate is not None and max_latency >= 0.25,
                   seen=sorted(seen), max_latency_seconds=max_latency)
        decision = self.decide("original-network-rate", [observation(initial_rate, "rate")])["rate"]
        recovered = recover(self.worker, initial_rate, decision["delay_seconds"])
        self.decide("original-network-recovered", [observation(recovered["recovered"], "normal")])
        self.check("original-network-rate-recovery", True, initial=initial_rate, decision=decision, **recovered)

    def budget_client(self):
        # This is a client allowance check, not proof of exhausting the server's 120 quota.
        before = self.worker.calls
        records = [self.worker.call("request", case="session") for _ in range(3)]
        decision = self.decide("client-budget-stop", [{"id": "budget", "remaining_client_allowance": 0,
                              "server_request_limit": 120, "completed_client_requests": 3}])["budget"]
        self.check("client-allowance-stop", all(record["status"] == 200 for record in records)
                   and self.worker.calls == before + 3, decision=decision,
                   server_quota_exhaustion_measured=False, application_requests_after_stop=0)

    def budget_server(self):
        last = None
        for _ in range(119):
            last = self.worker.call("request", case="session")
            if last["status"] != 200 or not last["own_account"]:
                raise meta.ProbeStopped("Unexpected response while measuring the exact server quota.")
        exhausted = self.worker.call("request", case="session")
        body = json.loads(exhausted["body_redacted"])
        facts = {"id": "budget", "status": exhausted["status"], "body": {"error": body.get("error")},
                 "remaining_client_allowance": 0, "server_request_limit": 120,
                 "headers": {"Retry-After": exhausted["headers"].get("retry-after")}}
        decision = self.decide("server-budget-stop", [facts])["budget"]
        self.check("server-120-quota-exhaustion", last["status"] == 200 and exhausted["status"] == 429
                   and body.get("error") == "budget_exhausted" and body.get("total_forwarded") == 120,
                   exhausted=exhausted, decision=decision, application_retries=0)

    def run(self, stage):
        if stage == "recovery":
            self.throttle()
            return
        phase = {"budget-client": "budget", "budget-server": "budget"}.get(stage, stage)
        self.worker.call("configure", phase=phase)
        self.login()
        if stage in {"network", "combined"}:
            self.challenge()
        if stage in {"large", "combined"}:
            self.large()
        if stage == "combined":
            self.cutoff()
        if stage in {"network", "combined"}:
            self.network()
        if stage == "budget-client":
            self.budget_client()
        if stage == "budget-server":
            self.budget_server()


def finish_stage(directory, stage, completion, provider, worker, restored, stopped):
    uses = [record.get("response", {}).get("usage") for record in provider.records]
    summary = {"stage": stage, "finished_at": meta.utc_now(), "checks": completion.checks,
               "checks_passed": sum(check["passed"] for check in completion.checks),
               "checks_executed": len(completion.checks), "provider_calls": len(provider.records),
               "measured_tokens": sum(item.get("total_tokens", 0) for item in uses if item),
               "unknown_usage_calls": sum(item is None for item in uses), "lab_http_calls": worker.calls,
               "original_restored": restored, "stopped_reason": stopped,
               "complete": stopped is None and bool(completion.checks)
               and all(check["passed"] for check in completion.checks) and restored.get("restored") is True,
               "security_discovery_STOP_preserved": True,
               "model_received_full_large_bodies": False,
               "server_120_request_quota_exhaustion_measured": stage == "budget-server"
               and any(check["check"] == "server-120-quota-exhaustion" and check["passed"]
                       for check in completion.checks)}
    writer = meta.Probe(directory, provider.key)
    writer.save("summary.json", summary)
    manifest = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(directory.rglob("*")) if path.is_file() and not path.is_symlink()}
    writer.save("EVIDENCE-MANIFEST.json", manifest)
    print(json.dumps({key: value for key, value in summary.items()
                      if key not in {"checks", "original_restored"}}), flush=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--stages", default="recovery,large,network,combined")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    directory = args.workdir.resolve()
    stages = args.stages.split(",")
    if not directory.is_relative_to(meta.DATA_ROOT) or len(set(stages)) != len(stages) or any(
        stage not in STAGES for stage in stages):
        parser.error("Use distinct supported stages and a data-only workdir.")
    if (directory / "summary.json").exists():
        parser.error("Existing evidence cannot be overwritten.")
    scoped = lab.LabSSH.__new__(lab.LabSSH)
    scoped.directory = directory
    scoped.scope()
    active_scope = json.loads((directory / ".codex/scope.json").read_text())
    if "budget-server" in stages and not (
        active_scope["rules"].get("explicit_125_http_authorization") is True
        and active_scope["rules"]["http_request_budget"] == 125
    ):
        parser.error("The 125-call server quota proof needs an explicitly authorized 125-call scope.")
    baseline = json.loads((directory / "PRIOR-EVIDENCE-BASELINE.json").read_text())
    if not all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in baseline.items()):
        parser.error("Prior evidence baseline does not match.")
    if args.dry_run:
        print(json.dumps({"stages": stages, "provider_call_caps": {stage: STAGES[stage] for stage in stages},
                          "lab_http_cap_per_stage": active_scope["rules"]["http_request_budget"],
                          "network_requests": 0}))
        return 0
    key = lab.hidden_input("META_KEY")
    password = lab.hidden_input("SSH_PASSWORD")
    admin = None
    results = []
    stopped = None
    try:
        admin = lab.LabSSH(directory, password)
        password = ""
        for stage in stages:
            print(json.dumps({"event": "stage_started", "stage": stage}), flush=True)
            stage_dir = directory / stage
            (stage_dir / ".codex").mkdir(parents=True)
            (stage_dir / "provider/.codex").mkdir(parents=True)
            (stage_dir / ".codex/scope.json").write_bytes((directory / ".codex/scope.json").read_bytes())
            scope = json.loads((directory / "provider-scope.json").read_text())
            scope["rules"]["max_requests"] = STAGES[stage]
            (stage_dir / "provider/.codex/scope.json").write_text(json.dumps(scope, indent=2))
            provider = meta.Probe(stage_dir / "provider", key)
            provider.max_calls = STAGES[stage]
            provider.validate_scope(meta.body("Benign normalized functional observations"))
            admin.directory = stage_dir
            worker = None
            restored = {}
            completion = None
            stage_stopped = None
            try:
                worker = lab.WorkerSession(admin, "functional-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
                                          max_calls=125 if stage == "budget-server" else 120)
                completion = Completion(worker, provider)
                completion.run(stage)
                worker.call("snapshot")
                worker.call("trace")
            except (Exception, KeyboardInterrupt) as exc:
                stage_stopped = type(exc).__name__ + ": " + str(exc)
            finally:
                if worker:
                    try:
                        restored = worker.call("restore")
                        worker.close()
                        if not restored.get("restored"):
                            stage_stopped = (stage_stopped or "") + " Original lab was not restored."
                    except Exception as exc:
                        stage_stopped = (stage_stopped or "") + " Restore failed: " + type(exc).__name__
                if worker and completion:
                    results.append(finish_stage(stage_dir, stage, completion, provider, worker, restored, stage_stopped))
                provider.key = ""
            if stage_stopped:
                stopped = stage_stopped
                break
    except (Exception, KeyboardInterrupt) as exc:
        stopped = type(exc).__name__ + ": " + str(exc)
    finally:
        if admin:
            admin.close()
        password = key = ""
        summary = {"results": results, "finished_at": meta.utc_now(), "stopped_reason": stopped,
                   "complete": stopped is None and len(results) == len(stages)
                   and all(result["complete"] for result in results),
                   "provider_calls": sum(result["provider_calls"] for result in results),
                   "lab_http_calls": sum(result["lab_http_calls"] for result in results),
                   "measured_tokens": sum(result["measured_tokens"] for result in results),
                   "server_120_quota_test_pending": not any(result["server_120_request_quota_exhaustion_measured"]
                                                             for result in results),
                   "security_discovery_STOP_preserved": True}
        meta.Probe(directory, "").save("summary.json", summary)
        print(json.dumps({key: value for key, value in summary.items() if key != "results"}), flush=True)
    return 0 if summary["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
