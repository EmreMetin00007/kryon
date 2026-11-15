#!/usr/bin/env python3
"""Bounded functional resilience measurement; no discovery or exploit adapters."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import sys
import termios
import time
from pathlib import Path

try:
    import paramiko
except ImportError:  # pragma: no cover - optional SSH probe dependency
    paramiko = None  # type: ignore[assignment]

import meta_functional_probe as meta

HOST = "31.58.250.147"
PORT = 22
LAB = "http://31.58.250.147:18901"
REMOTE_LAB = "/root/crapi-lab"

INSPECT = r'''
from pathlib import Path
import json, urllib.request
root=Path('/root/crapi-lab')
paths=['proxy/main.py','app/main.py','evaluator/cli.py','profiles/b-session.yml','profiles/c-network.yml','profiles/e-budget.yml']
paths += [str(path.relative_to(root)) for path in sorted((root/'proxy').glob('*.py'))]
result={'active_run':str((root/'runs/active').resolve()),'sources':{}}
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
with opener.open('http://127.0.0.1:18901/proxy/health',timeout=10) as response:
 result['health']=json.load(response)
for name in paths:
 path=root/name
 if path.exists(): result['sources'][name]=path.read_text()
print(json.dumps(result))
'''


def hidden_input(label: str) -> str:
    if not sys.stdin.isatty():
        raise RuntimeError("Hidden credential input requires a terminal.")
    previous = termios.tcgetattr(sys.stdin.fileno())
    hidden = termios.tcgetattr(sys.stdin.fileno())
    hidden[3] &= ~(termios.ECHO | termios.ECHONL)
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSAFLUSH, hidden)
    try:
        print(label + "_READY (terminal echo disabled)", flush=True)
        value = sys.stdin.readline().rstrip("\r\n")
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSAFLUSH, previous)
        print(flush=True)
    if not value or any(ord(char) < 32 for char in value):
        raise RuntimeError("Missing or invalid secret input.")
    return value


_HOST_KEY_BASE = paramiko.MissingHostKeyPolicy if paramiko is not None else object
_SSH_EXCEPTIONS: tuple[type[BaseException], ...] = (
    (paramiko.SSHException,) if paramiko is not None else ()
)


class PinnedHostKey(_HOST_KEY_BASE):
    def __init__(self, path: Path):
        self.pin = json.loads(path.read_text())

    def missing_host_key(self, client, hostname, key):
        if paramiko is None:
            raise RuntimeError("paramiko is required for SSH host key verification.")
        if (hostname != HOST or key.get_name() != self.pin["algorithm"]
                or base64.b64encode(key.asbytes()).decode() != self.pin["public_key"]):
            raise paramiko.SSHException("Previously pinned SSH host key does not match.")
        client.get_host_keys().add(hostname, key.get_name(), key)


class LabSSH:
    def __init__(self, directory: Path, password: str):
        if paramiko is None:
            raise RuntimeError("paramiko is required for LabSSH.")
        self.directory = directory
        self.password = password
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(PinnedHostKey(directory / "ssh-host-public-key.json"))
        self.scope()
        meta.audit("lab-functional-ssh-connect", status="started", target=f"ssh://{HOST}:{PORT}")
        self.client.connect(HOST, port=PORT, username="root", password=password,
                            look_for_keys=False, allow_agent=False, timeout=12,
                            auth_timeout=12, banner_timeout=12)

    def scope(self):
        scope = json.loads((self.directory / ".codex/scope.json").read_text())
        assets = {entry["asset"] for entry in scope["in_scope"]}
        if scope.get("status") != "READY" or not {
            f"ssh://{HOST}:{PORT}", LAB, "http://127.0.0.1:18901"
        }.issubset(assets):
            raise RuntimeError("Exact lab and SSH assets must be in scope.")
        rules = scope.get("rules", {})
        if not (0 < rules.get("max_rps", 0) <= 2 and rules.get("max_concurrency") == 1
                and type(rules.get("http_request_budget")) is int
                and 1 <= rules["http_request_budget"] <= (125 if rules.get("explicit_125_http_authorization") is True else 120)
                and rules.get("no_dos") is True
                and rules.get("no_destructive") is True
                and rules.get("stop_on_unexpected_degradation") is True):
            raise RuntimeError("The fixed functional lab request limits must be present in scope.")

    def execute(self, name: str, source: str, timeout: int = 30) -> dict:
        self.scope()
        meta.audit("lab-functional-fixed-ssh-command", status="started", case=name,
                   workdir=str(self.directory))
        stdin, stdout, stderr = self.client.exec_command("python3 -", timeout=timeout)
        stdin.write(source)
        stdin.flush()
        stdin.channel.shutdown_write()
        channel = stdout.channel
        started = time.monotonic()
        output, errors = bytearray(), bytearray()
        while True:
            while channel.recv_ready():
                output.extend(channel.recv(65536))
            while channel.recv_stderr_ready():
                errors.extend(channel.recv_stderr(65536))
            if len(output) + len(errors) > 1_048_576 or time.monotonic() - started > timeout:
                channel.close()
                raise RuntimeError("Remote output or duration budget reached.")
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.05)
        code = channel.recv_exit_status()
        record = {"exit_code": code, "stdout": output.decode(errors="replace"),
                  "stderr": errors.decode(errors="replace")}
        writer = meta.Probe(self.directory, self.password)
        writer.save(name + ".json", record)
        meta.audit("lab-functional-fixed-ssh-result", status=code, case=name,
                   workdir=str(self.directory))
        if code:
            raise RuntimeError("Fixed remote operation failed; see preserved evidence.")
        return json.loads(record["stdout"].strip().splitlines()[-1])

    def close(self):
        self.client.close()
        self.password = ""
        meta.audit("lab-functional-ssh-close", status="completed", workdir=str(self.directory))


class WorkerSession:
    def __init__(self, admin: LabSSH, name: str, max_calls: int | None = None):
        self.admin = admin
        source = Path(__file__).with_name("lab_functional_worker.py").read_text()
        admin.scope()
        command = "python3 -u -c " + shlex.quote(source) + " " + shlex.quote(name)
        scope = json.loads((admin.directory / ".codex/scope.json").read_text())
        if max_calls is None:
            max_calls = min(39, scope["rules"]["http_request_budget"])
        limit = 125 if scope["rules"].get("explicit_125_http_authorization") is True else 120
        if not 1 <= max_calls <= min(limit, scope["rules"]["http_request_budget"]):
            raise RuntimeError("Worker budget exceeds the active scope.")
        command += " " + str(max_calls)
        self.stdin, self.stdout, self.stderr = admin.client.exec_command(command, timeout=90)
        self.directory = admin.directory / "worker-operations"
        self.directory.mkdir()
        self.writer = meta.Probe(self.directory, admin.password)
        self.number = 0
        self.calls = 0
        if json.loads(self.stdout.readline()) != {"ready": True}:
            raise RuntimeError("Fixed functional worker did not become ready.")

    def call(self, action: str, **options):
        self.admin.scope()
        self.number += 1
        request = {"action": action, **options}
        meta.audit("lab-functional-worker-operation", status="started", operation=request,
                   workdir=str(self.admin.directory))
        self.stdin.write(json.dumps(request) + "\n")
        self.stdin.flush()
        result = json.loads(self.stdout.readline())
        self.writer.save(f"{self.number:02d}-{action}.json", {"request": request, "response": result})
        if "number" in result:
            self.calls = result["number"]
        if "calls" in result:
            self.calls = result["calls"]
        if isinstance(result.get("health"), dict):
            self.calls = result["health"]["number"]
        meta.audit("lab-functional-worker-result", status="failed" if "error_class" in result
                   else "completed", operation=action, workdir=str(self.admin.directory),
                   observed_http_calls=self.calls)
        if "error_class" in result:
            raise RuntimeError("Fixed lab operation failed: " + result["error_class"])
        return result

    def wait(self, seconds):
        print(json.dumps({"event": "bounded_wait", "seconds": seconds}), flush=True)
        return self.call("wait", seconds=seconds)

    def close(self):
        self.stdin.write('{"action":"close"}\n')
        self.stdin.flush()
        self.stdin.channel.shutdown_write()
        code = self.stdout.channel.recv_exit_status()
        self.stdin.close()
        if code:
            raise RuntimeError("Functional worker ended with an error.")


def provider_observation(record: dict, case_id: str) -> dict:
    """Only normalized protocol facts may leave the host; never forward bodies or identities."""
    source = record["normalized"]
    result = {"id": case_id}
    for key in {"status", "json_parsed", "read_error", "bytes_received", "expected_events",
                "completed_events", "stream_incomplete", "read_complete"}:
        if key in source:
            result[key] = source[key]
    allowed_headers = {"retry-after": "Retry-After", "content-encoding": "Content-Encoding",
                       "x-lab-stream-cut": "X-Lab-Stream-Cut"}
    result["headers"] = {allowed_headers[key]: value for key, value in source.get("headers", {}).items()
                         if key in allowed_headers}
    if source.get("body") == {"error": "session_expired"}:
        result["body"] = {"error": "session_expired"}
        result["context"] = "The client owns the account and can renew its legitimate session."
    if source.get("body") == {"error": "upstream_unavailable"}:
        result["body"] = {"error": "upstream_unavailable"}
    return result


def valid_decision(item: dict, case_id: str, min_delay=0) -> bool:
    category, action, default_delay, usable = meta.EXPECTED[case_id]
    delay = item.get("delay_seconds")
    required = max(default_delay, min_delay)
    return (item.get("id") == case_id and item.get("category") == category
            and item.get("action") == action and item.get("payload_usable") is usable
            and type(delay) is int and required <= delay <= 60
            and (required > 0 or delay == 0))


class Measurement:
    def __init__(self, provider: meta.Probe, worker: WorkerSession, transient_only: bool = False):
        self.provider, self.worker = provider, worker
        self.transient_only = transient_only
        self.checks = []

    def decide(self, name: str, observations: list[dict]) -> dict:
        prompt = ("Choose safe HTTP client handling for these normalized observations from an "
                  "owned test service. Return one JSON decision per id. For 429 honor Retry-After; "
                  "for transient 502 wait at least one second before one retry. For an expired "
                  "owned session renew the legitimate session. Reject malformed encoding and "
                  "incomplete streams as usable data. Non-retry actions have delay zero. "
                  "Use category upstream_error with action backoff_retry for 502; use category "
                  "rate_limited with action wait_retry for 429. "
                  "No action needs more than 60 seconds of delay.\n" + json.dumps(observations))
        response = self.provider.request(name, meta.body(prompt, 1024, text={"format": {
            "type": "json_schema", "name": "http_client_decisions", "strict": True,
            "schema": meta.DECISION_SCHEMA}}))
        items = json.loads(meta.text_output(response))["decisions"]
        ids = [item["id"] for item in items]
        if response.get("model") != meta.MODEL or sorted(ids) != sorted(item["id"] for item in observations):
            raise meta.ProbeStopped("Unexpected model identity or decision case set.")
        return {item["id"]: item for item in items}

    def check(self, name, passed, **evidence):
        record = {"case": name, "passed": bool(passed), **evidence}
        self.checks.append(record)
        print(json.dumps({"event": "scenario_result", "case": name, "passed": bool(passed)}), flush=True)
        if not passed:
            raise meta.ProbeStopped("Functional scenario failed; stop without extra probes.")

    def run(self):
        if self.transient_only:
            self.run_transients()
            return
        w = self.worker
        w.call("configure", phase="session")
        initial = w.call("request", case="login")
        if initial["status"] != 200:
            raise meta.ProbeStopped("Synthetic account login failed.")
        w.wait(27)
        expired = w.call("request", case="session")
        if expired["status"] != 401 or expired["normalized"].get("body") != {"error": "session_expired"}:
            raise meta.ProbeStopped("Expected expired-session fixture was not observed.")
        decision = self.decide("session-renewal", [provider_observation(expired, "expiry")])["expiry"]
        if not valid_decision(decision, "expiry"):
            self.check("session-renewal", False, decision=decision)
        renewed = w.call("request", case="login")
        refreshed = w.call("request", case="refresh")
        verified = w.call("request", case="session")
        self.check("session-renewal", renewed["status"] == refreshed["status"] == verified["status"] == 200
                   and renewed["token_changed"] and refreshed["csrf_rotated"] and verified["own_account"],
                   decision=decision, expired=expired, renewed=renewed, refreshed=refreshed, verified=verified)

        encoded = [w.call("request", case="gzip"), w.call("request", case="utf8")]
        decisions = self.decide("encoding-errors", [provider_observation(record, case_id)
                                for record, case_id in zip(encoded, ["gzip", "utf8"])])
        for record, case_id, error in zip(encoded, ["gzip", "utf8"], ["gzip.BadGzipFile", "UnicodeDecodeError"]):
            self.check(case_id, record["status"] == 200 and record["decode_error"] == error
                       and valid_decision(decisions[case_id], case_id),
                       observation=record, decision=decisions[case_id], retries_executed=0)
        w.call("snapshot")

        w.call("configure", phase="cutoff")
        if w.call("request", case="login")["status"] != 200:
            raise meta.ProbeStopped("Cutoff fixture login failed.")
        cutoff = w.call("request", case="cutoff")
        decision = self.decide("stream-cutoff", [provider_observation(cutoff, "cutoff")])["cutoff"]
        self.check("cutoff", cutoff["status"] == 200 and cutoff["bytes_received"] == 2048
                   and cutoff["normalized"]["stream_incomplete"]
                   and cutoff["headers"].get("x-lab-stream-cut", "").startswith("after-2048")
                   and valid_decision(decision, "cutoff"), observation=cutoff, decision=decision, retries_executed=0)
        w.call("snapshot")

        self.run_transients()

    def run_transients(self):
        w = self.worker
        for phase, case_id, expected_status in [("gateway", "gateway", 502), ("throttle", "throttle", 429)]:
            w.call("configure", phase=phase)
            if w.call("request", case="login")["status"] != 200:
                raise meta.ProbeStopped("Transient-error fixture login failed.")
            fault = None
            for _ in range(4):
                record = w.call("request", case="session")
                if record["status"] == expected_status:
                    fault = record
                    break
                if record["status"] != 200 or not record["own_account"]:
                    raise meta.ProbeStopped("Unexpected lab response before intended fault.")
            if fault is None:
                raise meta.ProbeStopped("Configured error fixture was not observed within its budget.")
            minimum = int(fault["headers"]["retry-after"]) if phase == "throttle" else 1
            decision = self.decide(phase + "-recovery", [provider_observation(fault, case_id)])[case_id]
            if not valid_decision(decision, case_id, minimum):
                self.check(phase, False, decision=decision, observation=fault)
            wait = w.wait(decision["delay_seconds"] + (0.25 if phase == "throttle" else 0))
            recovered = w.call("request", case="session")
            self.check(phase, recovered["status"] == 200 and recovered["own_account"]
                       and wait["waited_seconds"] >= minimum,
                       decision=decision, observation=fault, wait=wait, recovered=recovered, retries_executed=1)
            w.call("snapshot")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workdir", required=True, type=Path)
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--transient-only", action="store_true")
    parser.add_argument("--resume-from", type=Path)
    args = parser.parse_args()
    directory = args.workdir.resolve()
    if not directory.is_relative_to(meta.DATA_ROOT):
        parser.error("Working data must stay below /root/cco-work.")
    if args.transient_only != bool(args.resume_from):
        parser.error("Use --transient-only together with --resume-from.")
    scoped = LabSSH.__new__(LabSSH)
    scoped.directory = directory
    scoped.scope()
    baseline = json.loads((directory / "PRIOR-EVIDENCE-BASELINE.json").read_text())
    if not all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
               for path, digest in baseline.items()):
        parser.error("Prior evidence differs from the preserved baseline; stop.")
    if not args.inspect and (directory / "summary.json").exists():
        parser.error("Completed or partial evidence cannot be overwritten; use a fresh run.")
    provider = meta.Probe(directory / "provider", "")
    prior_summary = None
    if args.transient_only:
        provider.max_calls = 2
        previous = args.resume_from.resolve()
        if not previous.is_relative_to(meta.DATA_ROOT) or previous == directory:
            parser.error("Resume evidence must be a separate data directory.")
        prior_summary = json.loads((previous / "summary.json").read_text())
        if not (prior_summary.get("complete") is False and prior_summary.get("checks_passed") == 4
                and {check["case"] for check in prior_summary["checks"] if check["passed"]}
                == {"session-renewal", "gzip", "utf8", "cutoff"}
                and prior_summary["original_restored"].get("restored") is True):
            parser.error("Resume requires the preserved four passing initial scenarios and restored lab.")
    provider.validate_scope(meta.body("Benign normalized client observations"))
    if args.dry_run:
        print(json.dumps({"provider_max_calls": provider.max_calls,
                          "lab_max_calls": 20 if args.transient_only else 40,
                          "planned_scenarios": 2 if args.transient_only else 6,
                          "provider_calls": 0, "vds_calls": 0}))
        return 0
    if not args.inspect:
        provider.key = hidden_input("META_KEY")
    password = hidden_input("SSH_PASSWORD")
    client = None
    worker = None
    measurement = None
    stopped = None
    restored = None
    try:
        client = LabSSH(directory, password)
        password = ""
        if args.inspect:
            result = client.execute("remote-inspection", INSPECT)
            print(json.dumps({"health": result["health"], "active_run": result["active_run"],
                              "source_files": list(result["sources"])}), flush=True)
        else:
            worker = WorkerSession(client, "functional-" + directory.name.rsplit("-", 1)[1])
            measurement = Measurement(provider, worker, args.transient_only)
            measurement.run()
    except (meta.ProbeStopped, RuntimeError, OSError, ValueError, KeyError, TypeError,
            *_SSH_EXCEPTIONS, KeyboardInterrupt) as exc:
        stopped = type(exc).__name__ + ": " + str(exc)
    finally:
        password = ""
        if worker:
            try:
                restored = worker.call("restore")
                worker.close()
            except Exception as exc:
                stopped = (stopped or "") + " Restore/close failed: " + type(exc).__name__
        if client:
            client.close()
        if not args.inspect:
            checks = measurement.checks if measurement else []
            usage = [record.get("response", {}).get("usage") for record in provider.records]
            planned_checks = 2 if args.transient_only else 6
            complete = (stopped is None and len(checks) == planned_checks and all(check["passed"] for check in checks)
                        and len(provider.records) == provider.max_calls and restored and restored.get("restored") is True)
            summary = {"activity": "actual owned-lab functional HTTP client resilience",
                       "finished_at": meta.utc_now(), "checks": checks, "planned_checks": planned_checks,
                       "checks_passed": sum(check["passed"] for check in checks),
                       "checks_executed": len(checks), "provider_calls": len(provider.records),
                       "measured_tokens": sum(item.get("total_tokens", 0) for item in usage if item),
                       "provider_calls_with_unknown_usage": sum(item is None for item in usage),
                       "lab_http_calls": (worker.calls if worker else 0) + (0 if args.transient_only else 1),
                       "original_restored": restored, "stopped_reason": stopped,
                       "complete": bool(complete), "security_discovery_STOP_preserved": True,
                       "resume_from": str(args.resume_from) if args.resume_from else None,
                       "prior_summary_sha256": hashlib.sha256((args.resume_from / "summary.json").read_bytes()).hexdigest()
                       if args.resume_from else None,
                       "successful_scenarios_across_runs": sorted({check["case"] for check in checks if check["passed"]}
                           | ({check["case"] for check in prior_summary["checks"] if check["passed"]}
                              if prior_summary else set())),
                       "limitations": [f"This run planned {planned_checks} functional scenarios with dedicated fixture settings.",
                                       "Fixed host code carries out allowed model decisions; no open-ended agent discovery.",
                                       "Results do not measure security discovery or service load capacity."]}
            writer = meta.Probe(directory, provider.key)
            writer.save("summary.json", summary)
            manifest = {str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in sorted(directory.rglob("*")) if path.is_file()
                        and not path.is_symlink() and path.name != "EVIDENCE-MANIFEST.json"}
            writer.save("EVIDENCE-MANIFEST.json", manifest)
            meta.audit("lab-functional-measurement-finished", status="completed" if complete else "stopped",
                       workdir=str(directory), provider_calls=len(provider.records),
                       checks_passed=summary["checks_passed"], lab_http_calls=summary["lab_http_calls"])
            provider.key = ""
            print(json.dumps({key: value for key, value in summary.items()
                              if key not in {"checks", "original_restored"}}), flush=True)
    return 0 if stopped is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
