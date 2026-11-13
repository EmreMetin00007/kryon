"""Native OpenCode integration; only the model is scripted.

Run with PYTHONPATH=scripts and -m integration. Missing socket/namespace
permissions FAIL these tests, rather than producing a misleading green skip.
The comparison fixture is synthetic and is never full-agent acceptance evidence.
All servers bind loopback; all credentials and private-state canaries are new.
"""
from __future__ import annotations

from contextlib import contextmanager
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import gzip
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urljoin, urlsplit

import pytest

import full_agent_launcher as launcher
import full_agent_preflight as preflight
from fixtures.native_compat import stage_native_compat_assets
from full_agent_broker import CATALOG, dump
from orchestration_spec import TaskSpec, render_task_prompt, validate_worker_prompt
from test_http_chromium_acceptance import evidence as acceptance_evidence


pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = Path("/tmp/cco-work/full-agent-integration")
MODELS = {"planner": "integration/planner", "worker": "integration/worker",
          "worker_selection": "explicit",
          "credentials": "provider runtime only; never stored in benchmark artifacts"}
SECRET_ENV = ("CCO_BENCHMARK_API_KEY", "INTEGRATION_API_KEY", "OPENAI_API_KEY",
              "CCO_VAULT_KEY", "AWS_SECRET_ACCESS_KEY", "CCO_PREFLIGHT_HOST_SENTINEL")


# These helpers run as native worker bash tools inside the production solver
# sandbox. They can verify public evidence but cannot sign or access host keys.
CLOSURE_PREPARE = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import brain
work = Path(sys.argv[2])
live = json.loads((work / 'access/live-result.json').read_text())
row, = live['validations']
assert row['vuln_class'] == 'open_redirect' and row['verdict'] == 'CONFIRMED'
ledger = brain.ledger_mod.load_ledger(work)
assert {entry['vector'] for entry in ledger['hypotheses']} == set(brain.ledger_mod.DEFAULT_VECTORS)
for entry in ledger['hypotheses']:
    vector = entry['vector']
    args = ['hypotheses', 'mark', '--workdir', str(work), '--vector', vector,
            '--evidence', 'access/live-result.json']
    if vector == 'authn-session':
        args += ['--status', 'confirmed', '--validation-id', row['validation_id']]
    else:
        args += ['--status', 'not_applicable', '--note',
                 'not_tested: auth:not-required: public redirect-only closure slice; '
                 + vector + ' was not exercised; broader security coverage remains unproven']
    assert brain.main(args) == 0
print('CLOSURE_VECTORS_PREPARED')
'''


CLOSURE_INTEGRITY = r'''
import json, subprocess, sys
from pathlib import Path
work = Path(sys.argv[2])
command = [sys.executable, str(Path(sys.argv[1]) / 'brain.py'),
           'closure', 'verify', '--workdir', str(work)]
def verify(expected):
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert result.returncode == expected, result.stdout + result.stderr
    return {'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
baseline = verify(0)
closure_path, attempt_path = work / 'closure.json', work / 'attempts.jsonl'
original_closure, original_attempts = closure_path.read_bytes(), attempt_path.read_bytes()
record, = [json.loads(line) for line in original_attempts.splitlines()]
outcomes = {}
def corrupt(signature):
    return ('0' if signature[0] != '0' else '1') + signature[1:]
for kind in ('closure_payload', 'closure_signature', 'attempt_verdict', 'attempt_signature', 'attempt_removed'):
    try:
        if kind.startswith('closure_'):
            changed = json.loads(original_closure)
            if kind == 'closure_payload':
                changed['payload']['target'] += '?post_seal_tamper=1'
            else:
                changed['signature'] = corrupt(changed['signature'])
            closure_path.write_text(json.dumps(changed))
        elif kind == 'attempt_removed':
            attempt_path.write_bytes(b'')
        else:
            changed = dict(record)
            if kind == 'attempt_verdict':
                changed['verdict'] = 'UNCONFIRMED'
            else:
                changed['signature'] = corrupt(changed['signature'])
            attempt_path.write_text(json.dumps(changed) + '\n')
        outcomes[kind] = verify(2)
    finally:
        closure_path.write_bytes(original_closure)
        attempt_path.write_bytes(original_attempts)
    outcomes[kind]['restored'] = verify(0)
assert closure_path.read_bytes() == original_closure
assert attempt_path.read_bytes() == original_attempts
(work / 'report/closure-integrity.json').write_text(json.dumps({
    'source': 'native_bash_cli_with_pinned_public_trust', 'command': command,
    'baseline': baseline, 'tampered': outcomes, 'restored': verify(0),
    'original_bytes_restored': True}))
print('CLOSURE_INTEGRITY_VERIFIED')
'''


# Runs INSIDE the production solver mount/network/PID namespaces. It tries
# open(), not just exists(), and proves useful mounts work in the same process.
# The host supplies paths only; no expected secret value enters this script.
ISOLATION_PROBE = r'''
import json, os, pathlib, signal, socket, subprocess, sys, time
p = pathlib.Path
work = p(os.environ['CCO_WORKDIR'])
if len(sys.argv) > 1 and sys.argv[1] == '--hang':
    child = subprocess.Popen([sys.executable, '-I', '-c',
        'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(180)'])
    (work / 'native-blocked.json').write_text(json.dumps({'pid': os.getpid(), 'child': child.pid}))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child.wait()
    raise SystemExit(0)
context = json.loads(sys.argv[1])
private = work.parent / 'private'
runtime = work.parent / 'runtime'
hidden = [
    private / 'state/evidence_signing.key',
    private / 'state/vault.key',
    private / 'state/credential_vault.db',
    private / 'state/session_vault.json',
    private / 'budget.json',
    p(context['source']) / 'tests/answers.py',
    p(context['source']) / 'credential_vault.db',
    p(context['source']) / 'previous/opencode.db',
    p(context['source']) / 'previous/native-events.jsonl',
    p(context['source']) / 'previous/answer.txt',
    p(context['repo']) / 'scripts/lab/blind_lab.py',
    runtime / 'tests/answers.py',
    runtime / 'scripts/lab/blind_lab.py',
    p('/root/.local/share/opencode/opencode.db'),
    p('/root/.config/opencode/auth.json'),
]
hidden += [p(run) / name for run in context['previous_runs']
           for name in ('private/native-events.jsonl', 'private/state/session_vault.json',
                        'solver/isolation-proof.json')]
hidden += [p(path) for path in context['previous_evidence_paths']]
hidden += [p(path) for path in context.get('family_private_paths', [])]
hidden += [p(context['source']).parent / 'acceptance.json',
           p(context['source']).parent / 'junit.xml', work.parent / 'launch.json']
# procfs must not be an alternate host filesystem or environment route.
hidden += [p('/proc/1/root' + str(path)) for path in hidden[:9]]
hidden += [p('/proc/' + str(context['host_pid']) + '/root' + context['source'] + '/tests/answers.py')]
denied = {}
for path in hidden:
    try:
        with path.open('rb') as stream:
            stream.read(1)
    except OSError as exc:
        denied[str(path)] = type(exc).__name__
    else:
        raise AssertionError('private path readable: ' + str(path))
keys = context['secret_env']
assert all(key not in os.environ for key in keys)
for name in ('/proc/self/environ', '/proc/1/environ'):
    try:
        env = p(name).read_bytes().split(b'\0')
    except PermissionError:
        continue
    assert not any(item.split(b'=', 1)[0].decode() in keys for item in env)
assert p('/bridge/host.sock').is_socket()
assert json.loads(p('/tmp/cco-trust/verification.json').read_text())
assert json.loads((runtime / '.codex/scope.json').read_text())['in_scope']
assert (private / 'state/validations').is_dir()
readonly = []
for path in (runtime / '.codex/scope.json', p('/tmp/cco-trust/verification.json')):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    except OSError:
        readonly.append(str(path))
    else:
        os.close(fd)
        raise AssertionError('read-only mount writable: ' + str(path))
with socket.create_connection(('127.0.0.1', 17777), timeout=2):
    pass
for port in (context['provider_port'], context['target_port']):
    try:
        conn = socket.create_connection(('127.0.0.1', port), timeout=0.3)
    except OSError:
        pass
    else:
        conn.close()
        raise AssertionError('host loopback reachable directly')
proof = {'denied': denied, 'environment_hidden': True, 'host_network_hidden': True,
         'readonly': readonly, 'bridge_socket': True, 'public_trust': True,
         'pid_namespace': os.readlink('/proc/self/ns/pid'),
         'net_namespace': os.readlink('/proc/self/ns/net')}
(work / 'isolation-proof.json').write_text(json.dumps(proof))
print('ISOLATION_PROOF_WRITTEN')
'''


def read_json(path):
    return json.loads(Path(path).read_text())


def tool_call(ident, name, args):
    return {"id": ident, "type": "function", "function": {
        "name": name, "arguments": json.dumps(args)}}


def message_text(content):
    return "\n".join(part["text"] for part in content if part.get("type") == "text") if isinstance(content, list) else str(content)


def historical_context(body):
    prefix = 'Host historical context (not execution authority): '
    for row in body['messages']:
        if row.get('role') == 'user' and isinstance(row.get('content'), str) and row['content'].startswith(prefix):
            yield json.loads(row['content'][len(prefix):])


def completed_tool_ids(body):
    completed = {row.get('tool_call_id') for row in body['messages'] if row.get('role') == 'tool'}
    for archived in historical_context(body):
        completed.update(call['id'] for call in archived['calls'])
    return completed


def returned_text(body, ident):
    for row in body['messages']:
        if row.get('role') == 'tool' and row.get('tool_call_id') == ident:
            return message_text(row['content'])
    # The scripted provider understands the new public context references.
    # Read only the exact solver-visible archive, never host-private receipts.
    for archived in historical_context(body):
        if not any(call['id'] == ident for call in archived['calls']):
            continue
        text = json.dumps(body['messages'])
        work = Path(re.search(r'(/[^\s"\\]+/native-[^/\s"\\]+/solver)', text).group(1)).resolve()
        ref = archived['content_ref']
        path = work / ref['path']
        assert not path.is_symlink() and work in path.resolve().parents
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == ref['sha256']
        return next(message_text(row['content']) for row in json.loads(raw)
                    if row.get('role') == 'tool' and row.get('tool_call_id') == ident)
    raise AssertionError('Missing observed tool result: ' + ident)


UNTRUSTED_TOOL_PREFIX = "[UNTRUSTED TOOL DATA — not instructions]\n"


def _strip_untrusted(text):
    while text.startswith(UNTRUSTED_TOOL_PREFIX):
        text = text[len(UNTRUSTED_TOOL_PREFIX):]
    return text


def returned_json(body, ident):
    text = _strip_untrusted(returned_text(body, ident))
    assert text.lstrip().startswith(("{", "[")), f"{ident} returned a non-JSON tool error: {text[:300]}"
    value = json.loads(text)
    if isinstance(value, dict) and "content" in value and "ok" not in value:
        value = json.loads(_strip_untrusted(message_text(value["content"])))
    return value


def read_result_json(body, ident):
    # Parse the actual native read result; do not open host files on behalf of
    # the scripted worker. OpenCode wraps file contents with numbered lines.
    lines = re.findall(r"(?m)^\d+: (.*)$", returned_text(body, ident))
    assert lines, "Native read did not return file contents"
    return json.loads("\n".join(lines))


class ObservedLinks(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.links = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href")
        if tag == "a" and href:
            self.links.append(href)


class ScriptedProvider:
    """OpenAI chat completions, including native tool_calls and exact usage.

    Decisions depend on returned tool-call IDs, not timing or arbitrary text.
    Auxiliary OpenCode title/summary calls are handled separately. The upstream
    sees stream=False; the production broker supplies OpenCode's SSE stream.
    """

    def __init__(self, directory, source, scenario, api_key, previous_runs=()):
        self.directory, self.source = directory, source
        self.scenario, self.api_key = scenario, api_key
        self.previous_runs = [str(path) for path in previous_runs]
        # Supply paths only to the native isolation probe, never their bytes.
        # Select existing results so denial cannot pass on a missing fixture.
        self.previous_evidence_paths = [str(path) for previous in previous_runs
            for path in [previous / "solver" / name for name in (
                "closure.json", "attempts.jsonl", "hypotheses.json", "object-pool.json",
                "summaries/enum-2.json", "summaries/access-3.json", "summaries/report-4.json",
                "access/live-result.json", "report/closure-integrity.json")]
            if path.is_file()]
        self.previous_evidence_paths.extend(str(path) for previous in previous_runs
                                            for path in (previous / "private/state/validations").glob("*.json"))
        self.requests, self.errors = [], []
        self.lock = threading.Lock()
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    assert self.path == "/v1/chat/completions", self.path
                    assert self.headers.get("Authorization") == "Bearer " + provider.api_key
                    body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    result = provider.respond(body)
                    raw = gzip.compress(json.dumps(result).encode())
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Encoding", "gzip")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as exc:
                    with provider.lock:
                        provider.errors.append(str(exc))
                        dump(provider.directory / "provider-errors.json", provider.errors)
                    self.send_error(500, "scripted provider contract failed")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        assert self.server.server_port != 17777
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def respond(self, body):
        assert body["stream"] is False
        assert body["model"] in {"planner", "worker"}
        assert 0 < body["max_tokens"] <= 8192
        available = {row["function"]["name"] for row in body.get("tools", [])}
        completed = completed_tool_ids(body)
        text = json.dumps(body["messages"])
        calls, content = [], "Integration complete; acceptance remains unverified."
        if available:
            contract_read = False
            if body["model"] == "planner":
                assert available == {"task", "read"}, "Planner must expose only delegation and pointer reads"
            else:
                match = re.search(r"Tools: ([^\\\n]+)", text)
                if match is None:
                    phase = re.search(r'Read (recon|enum|access|report)/task-context.txt; refs under Workdir.', text).group(1)
                    contract_id = 'it-' + phase + '-contract-read'
                    assert contract_id not in completed
                    # Consume the actual persisted host contract through a
                    # native read before validating its Commands/Tools again.
                    contract_work = Path(re.search(r"(/[^\s\"\\]+/native-[^/\s\"\\]+/solver)", text).group(1))
                    calls = [tool_call(contract_id, 'read', {
                        'filePath': str(contract_work / phase / 'task-context.txt'), 'limit': 2000})]
                    contract_read = True
                else:
                    expected = {part.strip() for part in match.group(1).split(',')}
                    missing = expected - available
                    assert not missing, "Native MCP catalog incomplete: " + ", ".join(sorted(missing))
                    assert available == expected | {"read", "write", "edit", "bash"}
                    assert "Commands:" in text, "Host must render the actual native worker prompt"
            # The native prompt carries the exact dynamically allocated lab URL
            # and solver directory. Worker task prompts retain these references.
            base = re.search(r"http://127\.0\.0\.1:\d+/", text).group()
            work = Path(re.search(r"(/[^\s\"\\]+/native-[^/\s\"\\]+/solver)", text).group(1))
            context = {"source": str(self.source), "repo": str(ROOT),
                       "host_pid": os.getpid(), "secret_env": SECRET_ENV,
                       "previous_runs": self.previous_runs,
                       "previous_evidence_paths": self.previous_evidence_paths,
                       "provider_port": self.server.server_port,
                       "target_port": int(base.split(":")[2].rstrip("/"))}
            if contract_read:
                pass
            elif body["model"] == "planner":
                if "it-delegate" not in completed:
                    calls = [tool_call("it-delegate", "task", {
                        "description": "Local integration worker", "subagent_type": "worker", "prompt": "TaskSpec: recon-1"})]
                elif "it-planner-http" not in completed:
                    calls = [tool_call("it-planner-http", "task", {
                        "description": "Local integration follow-up", "subagent_type": "worker", "prompt": "TaskSpec: enum-2"})]
                elif self.scenario.startswith("handoff") and "it-access" not in completed:
                    calls = [tool_call("it-access", "task", {
                        "description": "Consume actual host handoff", "subagent_type": "worker", "prompt": "TaskSpec: access-3"})]
                elif self.scenario in {"handoff_validation", "handoff_negative", "handoff_closure"} and "it-report" not in completed:
                    calls = [tool_call("it-report", "task", {
                        "description": "Review signed coverage and closure gaps", "subagent_type": "worker", "prompt": "TaskSpec: report-4"})]
            elif self.scenario in {"handoff_validation", "handoff_negative", "handoff_closure"} and "Task: report-4" in text:
                calls = self.report_steps(body, base, work, completed)
            elif self.scenario.startswith("handoff") and ("Task: enum-2" in text or "Task: access-3" in text):
                calls = self.handoff_steps(body, base, work, completed, "Task: access-3" in text)
            elif "Task: enum-2" in text:
                if "it-followup-http" not in completed:
                    calls = [tool_call("it-followup-http", "kali-tools_curl_request", {
                        "url": base + "?integration_actor=followup", "method": "GET"})]
            elif "it-write" not in completed:
                # Paths are data, not shell arguments. In particular pytest's
                # test_shutdown_* directory name must not be parsed as a
                # shutdown command by the conservative bash policy.
                probe = ISOLATION_PROBE.replace("context = json.loads(sys.argv[1])",
                                                f"context = json.loads({json.dumps(context)!r})", 1)
                calls = [tool_call("it-write", "write", {
                    "filePath": str(work / "isolation_probe.py"), "content": probe})]
            elif "it-denied-read" not in completed:
                calls = [tool_call("it-denied-read", "read", {
                    "filePath": str(work.parent / "private/state/credential_vault.db")})]
            elif "it-probe" not in completed:
                command = "python3 -I " + shlex.quote(str(work / "isolation_probe.py"))
                calls = [tool_call("it-probe", "bash", {
                    "command": command, "description": "Check solver filesystem and namespaces", "timeout": 10000})]
            elif "it-worker-http" not in completed:
                calls = [tool_call("it-worker-http", "kali-tools_curl_request", {
                    "url": base + "?integration_actor=worker", "method": "GET"})]
            elif self.scenario in {"timeout", "sigint"} and "it-hang" not in completed:
                if self.scenario == "timeout":
                    # Place the actual blocked MCP call near the shared deadline,
                    # before its own 15-second HTTP timeout can finish it.
                    remaining = read_json(work.parent / "private/budget.json")["remaining_seconds"]
                    time.sleep(max(0, remaining - 8))
                calls = [
                    tool_call("it-hang", "bash", {
                        "command": "python3 -I " + shlex.quote(str(work / "isolation_probe.py")) + " --hang",
                        "description": "Wait for the integration shutdown signal", "timeout": 180000}),
                    tool_call("it-slow-http", "kali-tools_curl_request", {
                        "url": base + "__integration_wait__", "method": "GET"}),
                ]
            elif self.scenario == "admission" and "it-summary" not in completed:
                # Deliberately grow only the synthetic next prompt, after a
                # real target call. This tests admission/lifecycle, not model
                # quality or the scripted provider's tokenization accuracy.
                content = "Synthetic admission boundary fixture. " * 24000
                calls = [tool_call("it-admission-read", "read", {
                    "filePath": str(work / "summaries/recon-1.json")})]
            elif "it-summary" not in completed:
                summary = {"phase": "recon", "target": base, "status": "done",
                           "evidence": [str(work / "isolation-proof.json")], "findings": [], "next": "enum-2"}
                calls = [tool_call("it-summary", "write", {
                    "filePath": str(work / "summaries/recon-1.json"), "content": json.dumps(summary)})]
            for call in calls:
                assert call["function"]["name"] in available, (call["function"]["name"], sorted(available))
        else:
            content = "Local integration"
        with self.lock:
            number = len(self.requests) + 1
            usage = {"prompt_tokens": 100 + number, "completion_tokens": 17,
                     "total_tokens": 117 + number,
                     "prompt_tokens_details": {"cached_tokens": 10},
                     "completion_tokens_details": {"reasoning_tokens": 3}}
            message = {"role": "assistant", "content": content if self.scenario == "admission" else None if calls else content}
            if calls:
                message["tool_calls"] = calls
            result = {"id": f"integration-{number}", "object": "chat.completion", "created": 1,
                      "model": body["model"], "choices": [{"index": 0, "message": message,
                      "finish_reason": "tool_calls" if calls else "stop"}], "usage": usage}
            if self.scenario == "invalid_usage" and "it-planner-http" in completed:
                result.pop("usage")
            self.requests.append({"request": body, "response": result, "authenticated": True})
            dump(self.directory / "provider-transcript.json", self.requests)
            return result

    def handoff_steps(self, body, base, work, completed, access):
        if access:
            if "it-handoff-read" not in completed:
                return [tool_call("it-handoff-read", "read", {"filePath": str(work / "handoff-access.json")})]
            packet = read_result_json(body, "it-handoff-read")
            assert packet["vector"] == "access" and not packet["truncated"]
            if "it-pool-read" not in completed:
                return [tool_call("it-pool-read", "read", {"filePath": str(work / "object-pool.json")})]
            pool = read_result_json(body, "it-pool-read")
            digest = hashlib.sha256(json.dumps(pool, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            assert packet["pool_sha256"] == digest and packet["untried"] == pool["candidates"]
            assert not pool["own_ids"] and len(packet["identities"]) == 3
            if "it-consumption-proof" not in completed:
                proof = {"source": "native_read_tool_results", "pool_sha256": digest,
                         "handoff_vector": packet["vector"], "identity_count": len(packet["identities"]),
                         "untried": packet["untried"], "declared_owned_ids": pool["own_ids"],
                         "security_validation_claimed": False}
                return [tool_call("it-consumption-proof", "write", {
                    "filePath": str(work / "access/handoff-consumed.json"), "content": json.dumps(proof)})]
            if "it-access-plan" not in completed:
                return [tool_call("it-access-plan", "hunter_run_web_loop", {"target": base, "live": False})]
            plan = returned_json(body, "it-access-plan")
            assert plan["ok"] and plan["mode"] == "PLAN" and plan["target"] == base
            assert plan["plan"] and not plan["errors"] and plan["requests_authorized"] == 0
            if self.scenario in {"handoff_validation", "handoff_negative", "handoff_closure"}:
                return self.validation_steps(body, base, work, completed)
            if "it-access-summary" not in completed:
                summary = {"phase": "access", "target": base, "status": "partial", "findings": [],
                    "evidence": [str(work / "access/handoff-consumed.json")], "next": "validation remains NOT TESTED",
                    "steps": [{"id": "handoff", "status": "done"}, {"id": "plan", "status": "done"},
                              {"id": "security-validation", "status": "not_tested"}]}
                return [tool_call("it-access-summary", "write", {
                    "filePath": str(work / "summaries/access-3.json"), "content": json.dumps(summary)})]
            return []
        if "it-enum-http" not in completed:
            return [tool_call("it-enum-http", "kali-tools_curl_request", {"url": base, "method": "GET"})]
        observed = returned_json(body, "it-enum-http")
        assert observed["ok"] and observed["status"] == 200
        links = ObservedLinks(observed["text"]).links
        assert links
        contents = "\n".join(message_text(row.get("content", "")) for row in body["messages"])
        match = re.search(r"(?m)^Synthetic session references \(host-owned\): (.+)$", contents)
        assert match, "Only supplied host references may enter the handoff"
        bindings = json.loads(match.group(1))
        for label in bindings:
            ident = "it-session-" + label
            if ident not in completed:
                return [tool_call(ident, "validator_session_vault_check", {"target": base, "identity": label})]
            assert returned_json(body, ident)["status"] == "fresh"
        if "it-enum-evidence" not in completed:
            return [tool_call("it-enum-evidence", "write", {
                "filePath": str(work / "enum/entry-response.json"), "content": json.dumps(observed)})]
        if "it-enum-summary" not in completed:
            queries = [(urlsplit(link).path, parse_qs(urlsplit(link).query)) for link in links]
            number = next(values["id"][0] for _, values in queries if "id" in values)
            filename = next(values["name"][0] for path, values in queries if path == "/file" and "name" in values)
            summary = {"phase": "enum", "target": base, "status": "partial", "findings": [],
                "evidence": [str(work / "enum/entry-response.json")], "next": "access-3",
                "steps": [{"id": "entry-links", "status": "done"}, {"id": "ownership", "status": "not_tested"}],
                "surface": {"routes": links, "params": sorted({key for _, values in queries for key in values}),
                    "docs": [], "docs_probes": [], "id_formats": [
                        {"family": "item", "format": "integer", "value": number},
                        {"family": "file", "format": "filename", "value": filename}]}}
            if self.scenario == "handoff_bad_summary":
                summary["surface"]["params"] = "invalid list shape"
            return [tool_call("it-enum-summary", "write", {
                "filePath": str(work / "summaries/enum-2.json"), "content": json.dumps(summary)})]
        if self.scenario == "handoff_missing":
            return []
        if "it-prepare-handoff" not in completed:
            return [tool_call("it-prepare-handoff", "kali-tools_ledger_prepare_handoff", {
                "target": base, "workdir": str(work), "summary_file": str(work / "summaries/enum-2.json"),
                "vector": "access", "own_ids_json": "[]", "session_bindings_json": json.dumps(bindings)})]
        handoff = returned_json(body, "it-prepare-handoff")
        if 'content_ref' in handoff:
            if 'it-handoff-full-read' not in completed:
                return [tool_call('it-handoff-full-read', 'read', {
                    'filePath': str(work / handoff['content_ref']['path']), 'limit': 2000})]
            handoff = read_result_json(body, 'it-handoff-full-read')
        assert handoff["ok"] is (self.scenario != "handoff_bad_summary"), handoff
        if "it-handoff-result" not in completed:
            return [tool_call("it-handoff-result", "write", {
                "filePath": str(work / "enum/handoff-result.json"), "content": json.dumps(handoff)})]
        return []

    def validation_steps(self, body, base, work, completed):
        # All candidate selection and verdicts come from the real host pipeline.
        # No evaluator truth, manufactured validator result or signing call is
        # available to this scripted solver.
        if "it-validation-surface" not in completed:
            return [tool_call("it-validation-surface", "read", {
                "filePath": str(work / "summaries/enum-2.json")})]
        if "it-access-live" not in completed:
            contents = "\n".join(message_text(row.get("content", "")) for row in body["messages"])
            match = re.search(r"(?m)^Synthetic session references \(host-owned\): (.+)$", contents)
            assert match, "LIVE must use observed host session references"
            bindings = json.loads(match.group(1))
            # Startup and prior phases can outlive the vault freshness window.
            # Refresh the real supplied references before LIVE, rather than
            # assuming setup/enum checks are still recent at access time.
            for label in bindings:
                ident = 'it-validation-session-' + label
                if ident not in completed:
                    return [tool_call(ident, 'validator_session_vault_check', {'target': base, 'identity': label})]
                assert returned_json(body, ident)['status'] == 'fresh'
            surface = read_result_json(body, "it-validation-surface")["surface"]
            # Select the observed redirect parameter, rather than the first
            # query-bearing link (/search). Search's multi-class fuzz plan
            # exhausts the default stuck allowance before validation starts.
            # A Location-header oracle needs only a few read-only requests
            # and never follows the external sentinel destination.
            negative = self.scenario == "handoff_negative"
            route = next(route for route in surface["routes"]
                         if urlsplit(route).path == ("/safe/go" if negative else "/go")
                         and "next" in parse_qs(urlsplit(route).query))
            observed_target = urljoin(base, route)
            assert urlsplit(observed_target).netloc == urlsplit(base).netloc
            return [tool_call("it-access-live", "hunter_run_web_loop", {
                "target": observed_target, "live": True, "crawl": False, "fuzz_limit": 16,
                "max_validations": 1, "candidate_sample_limit": 1 if negative else 0, "sleep_s": 0.2,
                "session_bindings": json.dumps(bindings)})]
        report = returned_json(body, "it-access-live")
        if 'content_ref' in report:
            if 'it-validation-full-read' not in completed:
                return [tool_call('it-validation-full-read', 'read', {
                    'filePath': str(work / report['content_ref']['path']), 'limit': 2000})]
            # Persist the actual host result, including discovery/fuzz and
            # blocked-work diagnostics, rather than the abbreviated view.
            report = read_result_json(body, 'it-validation-full-read')
        if "it-validation-output" not in completed:
            return [tool_call("it-validation-output", "write", {
                "filePath": str(work / "access/live-result.json"), "content": json.dumps(report, indent=2)})]
        if "it-access-coverage" not in completed:
            return [tool_call("it-access-coverage", "hunter_coverage_report", {"target": base})]
        coverage = returned_json(body, "it-access-coverage")
        if "it-coverage-output" not in completed:
            return [tool_call("it-coverage-output", "write", {
                "filePath": str(work / "access/coverage.json"), "content": json.dumps(coverage)})]
        if "it-access-summary" not in completed:
            summary = {"phase": "access", "target": base, "status": "partial",
                "findings": report.get("confirmed", []),
                "evidence": [str(work / "access/handoff-consumed.json"), str(work / "access/live-result.json"),
                             str(work / "access/coverage.json")], "next": "report-4; remaining vectors NOT TESTED",
                "steps": [{"id": "handoff", "status": "done"}, {"id": "plan", "status": "done"},
                          {"id": "bounded-validation", "status": "done" if report.get("validations") else "blocked"},
                          {"id": "remaining-security-coverage", "status": "not_tested"}]}
            return [tool_call("it-access-summary", "write", {
                "filePath": str(work / "summaries/access-3.json"), "content": json.dumps(summary)})]
        return []

    def report_steps(self, body, base, work, completed):
        if "it-report-live-read" not in completed:
            return [tool_call("it-report-live-read", "read", {
                "filePath": str(work / "access/live-result.json"), "limit": 2000})]
        live = read_result_json(body, "it-report-live-read")
        if "it-access-ledger" not in completed:
            # Invocation records never confer security confirmation authority.
            items = [{"vector": "authn-session" if self.scenario == "handoff_closure" else row["vuln_class"], "endpoint": row["url"],
                      "identity": row["identity"], "verdict": row["verdict"],
                      "artifact": "access/live-result.json", "note": row["validation_id"]}
                     for row in live.get("validations", []) if row.get("validation_id")]
            assert items, "Actual validation evidence is required before recording attempts"
            return [tool_call("it-access-ledger", "kali-tools_ledger_attempt_add_batch", {
                "workdir": str(work), "items_json": json.dumps(items)})]
        if "it-ledger-coverage" not in completed:
            vector = next((row["vuln_class"] for row in live.get("validations", [])), "access")
            if self.scenario == "handoff_closure":
                vector = "authn-session"
            return [tool_call("it-ledger-coverage", "kali-tools_ledger_coverage", {
                "workdir": str(work), "vector": vector})]
        if self.scenario == "handoff_closure":
            calls = self.closure_script_steps(body, work, completed, "prepare", CLOSURE_PREPARE)
            if calls:
                return calls
        if "it-checkpoint" not in completed:
            return [tool_call("it-checkpoint", "kali-tools_ledger_checkpoint", {
                "workdir": str(work), "seal": self.scenario in {"handoff_negative", "handoff_closure"}})]
        checkpoint = returned_json(body, "it-checkpoint")
        ledger = returned_json(body, "it-ledger-coverage")
        if "it-report-evidence" not in completed:
            return [tool_call("it-report-evidence", "write", {
                "filePath": str(work / "report/ledger.json"),
                "content": json.dumps({"checkpoint": checkpoint, "coverage": ledger})})]
        if self.scenario == "handoff_negative":
            calls = self.negative_integrity_steps(body, work, completed, ledger)
            if calls:
                return calls
        if self.scenario == "handoff_closure":
            assert checkpoint["sealed"] is True and checkpoint["check_exit"] == 0, checkpoint
            calls = self.closure_script_steps(body, work, completed, "integrity", CLOSURE_INTEGRITY)
            if calls:
                return calls
        if "it-report-summary" not in completed:
            summary = {"phase": "report", "target": base, "status": "partial", "findings": [],
                "evidence": [str(work / "access/coverage.json"), str(work / "report/ledger.json")],
                "next": "closure blocked: remaining vectors NOT TESTED; full paid acceptance unproven",
                "steps": [{"id": "signed-coverage-review", "status": "done"},
                          {"id": "ledger-checkpoint", "status": "done"}, {"id": "closure", "status": "blocked"}]}
            if self.scenario == "handoff_closure":
                summary["evidence"].extend([str(work / "closure.json"), str(work / "report/closure-integrity.json")])
                summary["next"] = "local closure verified; explicitly parked vectors and full paid acceptance remain NOT TESTED"
                summary["steps"][-1]["status"] = "done"
                summary["steps"].append({"id": "broader-security-coverage", "status": "not_tested"})
            return [tool_call("it-report-summary", "write", {
                "filePath": str(work / "summaries/report-4.json"), "content": json.dumps(summary)})]
        return []

    def closure_script_steps(self, body, work, completed, kind, script):
        path = work / ("closure_" + kind + ".py")
        write_id, run_id = "it-closure-" + kind + "-write", "it-closure-" + kind + "-run"
        if write_id not in completed:
            return [tool_call(write_id, "write", {"filePath": str(path), "content": script})]
        if run_id not in completed:
            command = shlex.join(["python3", str(path), str(work.parent / "runtime/scripts"), str(work)])
            return [tool_call(run_id, "bash", {"command": command,
                "description": "Prepare closure vectors" if kind == "prepare" else "Verify sealed closure and post-seal drift",
                "timeout": 120000})]
        marker = "CLOSURE_VECTORS_PREPARED" if kind == "prepare" else "CLOSURE_INTEGRITY_VERIFIED"
        assert marker in returned_text(body, run_id), returned_text(body, run_id)
        return []

    def negative_integrity_steps(self, body, work, completed, baseline):
        # The native worker can edit public attempt evidence, but has neither
        # the host signing key nor authority to make edited records trusted.
        if "it-negative-ledger-read" not in completed:
            return [tool_call("it-negative-ledger-read", "read", {
                "filePath": str(work / "attempts.jsonl")})]
        original = read_result_json(body, "it-negative-ledger-read")
        assert original["verdict"] == "UNCONFIRMED" and baseline["trusted_records"] == 1
        outcomes = {}
        # Keep the signature syntactically valid so coverage reaches its
        # cryptographic integrity check instead of rejecting the JSON schema.
        invalid_signature = ("0" if original["signature"][0] != "0" else "1") + original["signature"][1:]
        for kind, field, replacement in (("verdict", "verdict", "CONFIRMED"),
                                         ("signature", "signature", invalid_signature)):
            before = json.dumps(field) + ":" + json.dumps(original[field])
            after = json.dumps(field) + ":" + json.dumps(replacement)
            edit_id, coverage_id, restore_id = ("it-negative-" + kind + suffix
                                                for suffix in ("-edit", "-coverage", "-restore"))
            if edit_id not in completed:
                return [tool_call(edit_id, "edit", {"filePath": str(work / "attempts.jsonl"),
                                                    "oldString": before, "newString": after})]
            if coverage_id not in completed:
                return [tool_call(coverage_id, "kali-tools_ledger_coverage", {
                    "workdir": str(work), "vector": original["vector"]})]
            outcomes[kind] = returned_json(body, coverage_id)
            assert outcomes[kind].get("integrity_errors") and outcomes[kind]["trusted_records"] == 0, outcomes
            if restore_id not in completed:
                return [tool_call(restore_id, "edit", {"filePath": str(work / "attempts.jsonl"),
                                                       "oldString": after, "newString": before})]
        if "it-negative-restored-coverage" not in completed:
            return [tool_call("it-negative-restored-coverage", "kali-tools_ledger_coverage", {
                "workdir": str(work), "vector": original["vector"]})]
        restored = returned_json(body, "it-negative-restored-coverage")
        assert restored == baseline
        if "it-negative-integrity-output" not in completed:
            return [tool_call("it-negative-integrity-output", "write", {
                "filePath": str(work / "report/negative-integrity.json"),
                "content": json.dumps({"baseline": baseline, "tampered": outcomes, "restored": restored})})]
        return []

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()


def process_table():
    """PID plus start time prevents mistaking PID reuse for a leaked child."""
    result = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            result[int(path.parent.name)] = {"state": fields[0], "ppid": int(fields[1]),
                                            "pgid": int(fields[2]), "started": fields[19]}
        except (OSError, ValueError, IndexError):
            continue
    return result


class ProcessTree:
    def __init__(self, process):
        self.process, self.seen = process, {}
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.watch, daemon=True)
        self.thread.start()

    def watch(self):
        while not self.stop.is_set():
            table = process_table()
            owned = {self.process.pid}
            while True:
                children = {pid for pid, row in table.items() if row["ppid"] in owned}
                updated = owned | children
                if updated == owned:
                    break
                owned = updated
            self.seen.update({pid: table[pid] for pid in owned if pid in table})
            self.stop.wait(0.025)

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=5)

    def living(self):
        table = process_table()
        return {pid: row for pid, row in dict(self.seen).items() if pid in table
                and table[pid]["started"] == row["started"] and table[pid]["state"] not in {"Z", "X"}}

    def cleanup(self):
        # Only identities observed below this test's child may be terminated.
        for pid in sorted(self.living(), reverse=True):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.process.wait(timeout=10)
        self.finish()


@pytest.fixture(scope="module")
def kernel_support():
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="environment-", dir=ARTIFACT_ROOT))
    checks = []
    for binary in ("opencode", "bwrap"):
        checks.append({"name": binary, "ok": shutil.which(binary) is not None})
    try:
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
        checks.append({"name": "loopback_socket", "ok": True})
    except OSError as exc:
        checks.append({"name": "loopback_socket", "ok": False, "error": str(exc)})
    if all(row["ok"] for row in checks[:2]):
        checks.append(preflight.check_isolation(directory, shutil.which("bwrap"), shutil.which("opencode")))
    dump(directory / "environment.json", checks)
    if not all(row["ok"] for row in checks):
        pytest.fail(f"Real integration prerequisites unavailable: {checks}; evidence: {directory}")
    return directory


@pytest.fixture
def integration_run(kernel_support, tmp_path, monkeypatch, acceptance_evidence):
    """Real snapshot/contract replay, real CLI, real broker and MCP executors.

    A temporary source holds the real allowlisted runtime plus synthetic
    forbidden fixtures. Only its provider config is changed. The old offline
    comparison fixture exercises hash/replay plumbing, not benchmark quality.
    """
    junit, evidence_dir, _ = acceptance_evidence
    for path in evidence_dir.glob("*/automatic-campaign-controls.json"):
        row = read_json(path)
        row.update(lab_version="blind-lab/3")
        row["score"]["proven"] = 8
        dump(path, row)
    dump(evidence_dir.parent / "acceptance.json", {
        "status": "passed", "pytest_exit_code": 0, **preflight.assess_results(junit, evidence_dir)})
    reference = preflight.baseline_reference(evidence_dir.parent)
    source = tmp_path / "source"
    source.mkdir()
    # Mirror the runtime allowlist; never read .env, credentials or old sessions.
    # Historical native agent definitions live behind the test-only compat archive.
    roots = ("scripts", "mcp-servers", "config", "rules", ".claude/skills")
    candidates = [ROOT / name for name in ("pyproject.toml", "AGENTS.md", "CLAUDE.md")]
    for name in roots:
        candidates.extend((ROOT / name).rglob("*"))
    for path in candidates:
        relative = path.relative_to(ROOT)
        if path.is_file() and not path.is_symlink() and preflight.runtime_file(relative):
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    stage_native_compat_assets(source, runtime_file=preflight.runtime_file)
    canaries = {}
    for name in ("tests/answers.py", "credential_vault.db", "previous/opencode.db",
                 "previous/native-events.jsonl", "previous/answer.txt"):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        canaries[name] = secrets.token_hex(32)
        path.write_text(canaries[name])
    monkeypatch.setattr(preflight, "ROOT", source)
    previous_runs = []
    previous_canaries = []

    @contextmanager
    def run(scenario="normal", api_key_env="CCO_BENCHMARK_API_KEY", provider_class=ScriptedProvider, *,
            seed_index=0, holdout_family="", holdout_seed=None, child_script=None, token_budget=None):
        seed = holdout_seed if holdout_family else reference["seeds"][seed_index]
        directory = Path(tempfile.mkdtemp(prefix=scenario + "-", dir=ARTIFACT_ROOT))
        secret_values = {name: "integration-secret-" + secrets.token_hex(24) for name in SECRET_ENV}
        provider = provider_class(directory, source, scenario, secret_values[api_key_env], previous_runs)
        process = tree = None
        try:
            config = {"model": MODELS["planner"], "provider": {"integration": {
                "npm": "@ai-sdk/openai-compatible", "options": {"baseURL": provider.url},
                "models": {model: {"name": "Integration " + model,
                                   "limit": {"context": 200000, "output": 8192}}
                           for model in ("planner", "worker")}}}}
            dump(source / "opencode.json", config)
            frozen = directory / "preflight"
            if scenario in {"handoff_validation", "handoff_negative", "handoff_closure"}:
                holdout_args = ["--holdout-family", holdout_family, "--holdout-seed", str(seed)] if holdout_family else []
                assert preflight.main([
                    "--baseline", str(evidence_dir.parent), "--model", MODELS["planner"],
                    "--worker-model", MODELS["worker"], "--token-budget", str(token_budget or 2_000_000),
                    "--provider-config", str(source / "opencode.json"), "--solver-mode", "native",
                    "--output-dir", str(frozen),
                ] + holdout_args) == 0
                frozen = next(frozen.glob("preflight-*"))
            else:
                frozen.mkdir()
                contract = preflight.native_contract(reference, MODELS, token_budget or (
                    100000 if scenario == "admission" else 2_000_000))
                dump(frozen / "contract.json", contract)
                snapshot = preflight.prepare_runtime(frozen, MODELS)
                dump(frozen / "preflight.json", {"schema": preflight.SCHEMA, "mode": "preflight_only",
                     "status": "prerequisites_ready", "contract": str(frozen / "contract.json"),
                     "contract_sha256": preflight.sha256(frozen / "contract.json"), "runtime_snapshot": snapshot})
            # Replay with the real function before starting any native process.
            launcher.prepared_run(frozen)
            dump(directory / "fixture.json", {"synthetic_comparison": True, "scenario": scenario,
                                               "seed": seed,
                                               "kernel_checks": str(kernel_support / "environment.json")})
            output = directory / "runs"
            output.mkdir()
            env = {key: value for key, value in os.environ.items()
                   if key in {"PATH", "LANG", "LC_ALL", "PLAYWRIGHT_BROWSERS_PATH"}}
            # Retain only non-secret cache controls so child imports cannot
            # write bytecode caches into the repository. No credentials added.
            for _cache_key in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX", "TMPDIR"):
                if _cache_key in os.environ:
                    env[_cache_key] = os.environ[_cache_key]
            env.update(secret_values, PYTHONPATH=str(ROOT / "scripts"),
                       INTEGRATION_OUTPUT=str(output), INTEGRATION_SCENARIO=scenario)
            if scenario == "handoff_negative":
                # Test-fixture configuration only (not a production budget
                # increase): the finite redirect corpus is 13 requests
                # (baseline + rejected probes/controls) to one endpoint,
                # which exceeds the production default repeat gate of 10.
                # Allow that bounded corpus to finish in this child only;
                # the default gate regression stays in test_negative_coverage.
                env["CCO_STUCK_THRESHOLD"] = "32"
            # Three native workers and session refreshes need more startup and
            # execution headroom on small CI hosts. This is fixture timing, not
            # a paid-provider allowance or a latency acceptance measurement.
            timeout_seconds = 45 if scenario == "timeout" else (600 if scenario.startswith("handoff") else 120)
            command = [sys.executable, str(child_script or Path(__file__).resolve()), "--integration-child",
                       "--preflight", str(frozen / "preflight.json"), "--seed", str(seed),
                       "--provider-config", str(source / "opencode.json"), "--api-key-env", api_key_env,
                       "--output-dir", str(output), "--timeout-seconds", str(timeout_seconds),
                       "--execute"]
            with (directory / "launcher.stdout").open("w") as stdout, (directory / "launcher.stderr").open("w") as stderr:
                process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr,
                                           stdin=subprocess.DEVNULL, cwd=ROOT, start_new_session=True)
                tree = ProcessTree(process)
                yield {"directory": directory, "output": output, "provider": provider,
                       "process": process, "tree": tree,
                       "canaries": [*secret_values.values(), *canaries.values(), *previous_canaries],
                       "timeout_seconds": timeout_seconds,
                       "source": source, "previous_runs": list(previous_runs)}
        finally:
            if tree is not None:
                tree.cleanup()
            elif process is not None:
                process.kill()
                process.wait(timeout=10)
            provider.close()
            previous_runs.extend((directory / "runs").glob("native-*"))
            previous_canaries.extend(secret_values.values())

    return run


def diagnostic_summary(run):
    """Keep the native startup error visible without exposing test credentials."""
    summary = {"artifacts": str(run["directory"]), "returncode": run["process"].poll()}
    logs = [run["directory"] / "launcher.stderr"]
    if run["provider"].errors:
        summary["provider_errors"] = list(run["provider"].errors)
    for path in run["output"].glob("native-*/launch.json"):
        manifest = read_json(path)
        summary["launch"] = {key: manifest.get(key) for key in ("status", "exit_code", "llm_calls", "error")}
        logs.append(path.parent / "private/native-stderr.log")
        transport = path.parent / "private/transport-events.jsonl"
        if transport.is_file():
            summary["mcp_startup"] = [
                {key: row[key] for key in ("group", "method", "status", "error")}
                for row in (json.loads(line) for line in transport.read_text().splitlines())
                if row["method"] in {"initialize", "notifications/initialized", "tools/list"}
            ][-30:]
    for path in logs:
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            stream.seek(max(0, path.stat().st_size - 4000))
            tail = stream.read().decode("utf-8", errors="replace")
        tail = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", tail)
        for value in run["canaries"]:
            tail = tail.replace(value, "<redacted>")
        if tail.strip():
            summary[path.name] = tail[-2000:]
    return summary


def wait_for(run, predicate, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        if run["process"].poll() is not None:
            break
        time.sleep(0.05)
    pytest.fail("Native integration condition not reached: " + json.dumps(diagnostic_summary(run)))


def finished(run, expected, exit_code, delegations=None):
    run["process"].wait(timeout=max(150, run["timeout_seconds"] + 30))
    run["tree"].finish()
    assert run["process"].returncode == exit_code, diagnostic_summary(run)
    paths = list(run["output"].glob("native-*/launch.json"))
    assert len(paths) == 1
    manifest = read_json(paths[0])
    assert manifest["status"] == expected, diagnostic_summary(run)
    assert manifest["acceptance_passed"] is False
    assert manifest["llm_cost_usd"] is None
    private = paths[0].parent / "private"
    events = [json.loads(line) for line in (private / "native-events.jsonl").read_text().splitlines()]
    assert events, "Native OpenCode events must survive shutdown"
    budget, tools = read_json(private / "budget.json"), read_json(private / "tool-index.json")
    assert budget["used"] == manifest["budget"]["used"]
    assert budget["reserved"] == manifest["budget"]["reserved"]
    assert tools and any(row["origin"] == "solver" for row in tools)
    assert not run["provider"].errors, run["provider"].errors
    startup = [json.loads(line) for line in (private / "transport-events.jsonl").read_text().splitlines()]
    for group in CATALOG:
        handshake = [row for row in startup if row["group"] == group and row["method"] in {
            "initialize", "notifications/initialized", "tools/list"}]
        assert [(row["method"], row["status"], row["error"]) for row in handshake] == [
            ("initialize", 200, None), ("notifications/initialized", 202, None), ("tools/list", 200, None)]
    # Native task metadata is emitted by OpenCode; gate session IDs originate
    # in the installed JS plugin. Neither is invented by the fake provider.
    gates = read_json(private / "native-gates.json")
    task_gates = [row for row in gates if row["tool"] == "task" and row["allowed"]]
    expected_delegations = delegations if delegations is not None else (2 if expected in {
        "native_finished_unverified", "budget_invalid"} else 1)
    assert len(task_gates) == manifest["native_delegations"] == expected_delegations
    assert len(manifest["native_session_ids"]) >= 2
    assert all(row["session_id"] and row["call_id"] for row in gates)
    if expected in {"native_finished_unverified", "budget_invalid"}:
        assert any(event.get("type") == "tool_use" and event.get("part", {}).get("tool") in {"task", "subagent"}
                   for event in events)
    assert any(row["tool"] == "read" and not row["allowed"] and row["reason"] == "blocked_secret_path"
               for row in gates), "The real native security-gate plugin must reject a private read"
    # Completed host MCP subprocess PIDs are recorded by the real executor.
    pids = []
    for row in tools:
        execution = read_json(row["artifact"])["execution"]
        if execution and execution.get("result", {}).get("executor_pid"):
            pids.append(execution["result"]["executor_pid"])
    assert pids and all(pid != os.getpid() for pid in pids)
    deadline = time.monotonic() + 5
    while run["tree"].living() and time.monotonic() < deadline:
        time.sleep(0.05)
    living = run["tree"].living()
    dump(run["directory"] / "process-tree.json", {"observed": run["tree"].seen, "living_after_exit": living})
    assert len(run["tree"].seen) >= 5, "Must observe launcher, bwrap, bridge, OpenCode and MCP children"
    assert not living, f"Leaked native/host children: {living}"
    return manifest, private, budget, tools


def assert_isolated(run, private):
    proof = read_json(private.parent / "solver/isolation-proof.json")
    assert len(proof["denied"]) >= 20
    assert proof["environment_hidden"] and proof["host_network_hidden"]
    assert proof["bridge_socket"] and proof["public_trust"] and len(proof["readonly"]) == 2
    assert proof["pid_namespace"] != os.readlink("/proc/self/ns/pid")
    assert proof["net_namespace"] != os.readlink("/proc/self/ns/net")
    # Positive host-side controls prevent tests against nonexistent fixtures.
    assert (private / "state/evidence_signing.key").stat().st_size > 0
    assert (private / "state/credential_vault.db").stat().st_size > 0
    assert (private / "state/vault.key").stat().st_size > 0
    assert (run["source"] / "tests/answers.py").stat().st_size > 0
    assert (run["source"] / "previous/opencode.db").stat().st_size > 0
    for path in (run["source"].parent / "acceptance.json", run["source"].parent / "junit.xml",
                 private.parent / "launch.json"):
        assert path.stat().st_size > 0 and str(path) in proof["denied"]
    for previous in run["previous_runs"]:
        for name in ("private/native-events.jsonl", "private/state/session_vault.json", "solver/isolation-proof.json"):
            path = previous / name
            assert path.stat().st_size > 0 and str(path) in proof["denied"]
    for name in run["provider"].previous_evidence_paths:
        path = Path(name)
        assert path.stat().st_size > 0 and name in proof["denied"]
    solver_visible = [*list((private.parent / "runtime").rglob("*")),
                      *list((private.parent / "solver").rglob("*")),
                      private / "native-events.jsonl", run["directory"] / "provider-transcript.json"]
    for path in solver_visible:
        if path.is_file():
            data = path.read_bytes()
            assert not any(value.encode() in data for value in run["canaries"]), path


def test_native_planner_worker_shared_budget_and_fresh_sessions(integration_run, record_testsuite_property):
    previous = set()
    for api_key_env in ("CCO_BENCHMARK_API_KEY", "INTEGRATION_API_KEY"):
        with integration_run(api_key_env=api_key_env) as run:
            record_testsuite_property("full_agent_normal_" + api_key_env, str(run["directory"]))
            manifest, private, budget, tools = finished(run, "native_finished_unverified", 0)
            assert_isolated(run, private)
            assert manifest["effective_limits"]["seconds_per_seed"] == 120
            assert read_json(Path(manifest["preflight"]).parent / "contract.json")["limits"]["seconds_per_seed"] == 1800
            sessions = set(manifest["native_session_ids"])
            assert sessions.isdisjoint(previous), "Every launch must create fresh planner and worker sessions"
            previous |= sessions
            transcript = run["provider"].requests
            assert {row["request"]["model"] for row in transcript} == {"planner", "worker"}
            usage = sum(row["response"]["usage"]["total_tokens"] for row in transcript)
            assert manifest["llm_calls"] == len(transcript)
            assert budget["used"]["tokens"] == usage > 0
            assert [(row["model"], row["usage"], row["charged"]) for row in budget["events"]
                    if row["kind"] == "tokens"] == [
                        (row["request"]["model"], row["response"]["usage"], row["response"]["usage"]["total_tokens"])
                        for row in transcript]
            assert budget["reserved"] == {"http": 0, "tokens": 0}
            assert not budget["blocked"]
            http = [row for row in budget["events"] if row["kind"] == "http"]
            assert all(row["measurement_valid"] for row in budget["events"])
            assert {row["origin"] for row in http} == {"setup", "solver"}
            assert sum(row["charged"] for row in http) == manifest["target_requests"] == budget["used"]["http"]
            solver_calls = [read_json(row["artifact"])["execution"] for row in tools if row["origin"] == "solver"]
            assert len(solver_calls) == 2
            assert all(row["actual_request_cost"] == 1 and row["wire_usage"]["authorized_requests"] == 1
                       for row in solver_calls)
            assert len({row["wire_usage"]["invocation_id"] for row in solver_calls}) == 2
            setup_cost = sum(row["charged"] for row in http if row["origin"] == "setup")
            assert setup_cost > 0
            assert [row["reserved"] for row in http if row["origin"] == "solver"] == [
                300 - setup_cost, 299 - setup_cost]
            assert budget["used"]["http"] <= 300


@pytest.mark.parametrize("scenario", ["timeout", "sigint"])
def test_shutdown_kills_native_and_mcp_process_groups_and_keeps_evidence(integration_run, scenario, record_testsuite_property):
    with integration_run(scenario) as run:
        record_testsuite_property("full_agent_" + scenario, str(run["directory"]))
        wait_for(run, lambda: list(run["output"].glob("native-*/solver/native-blocked.json")),
                 timeout=50 if scenario == "timeout" else 90)
        wait_for(run, lambda: (run["output"] / "host-blocked.json").is_file(), timeout=5)
        assert run["tree"].living()
        started = time.monotonic()
        if scenario == "sigint":
            # Signal the actual CLI, not an injected KeyboardInterrupt.
            run["process"].send_signal(signal.SIGINT)
        manifest, private, budget, tools = finished(
            run, "interrupted" if scenario == "sigint" else "time_budget_exhausted",
            130 if scenario == "sigint" else 2)
        assert time.monotonic() - started < (15 if scenario == "sigint" else 55)
        assert_isolated(run, private)
        assert budget["used"]["tokens"] > 0 and budget["used"]["http"] >= manifest["target_requests"]
        assert any(row["origin"] == "solver" for row in tools)
        # An interrupted HTTP executor cannot refund an unmeasured reservation.
        interrupted = [row for row in budget["events"] if row["kind"] == "http" and not row["measurement_valid"]]
        assert interrupted and all(row["charged"] == row["reserved"] > 0 for row in interrupted)


def test_invalid_real_provider_usage_stops_native_without_refunding(integration_run, record_testsuite_property):
    with integration_run("invalid_usage") as run:
        record_testsuite_property("full_agent_invalid_usage", str(run["directory"]))
        manifest, private, budget, _ = finished(run, "budget_invalid", 2)
        assert_isolated(run, private)
        assert budget["blocked"] == "missing or invalid tokens usage"
        invalid = [row for row in budget["events"] if row["kind"] == "tokens" and not row["measurement_valid"]]
        assert len(invalid) == 1
        assert invalid[0]["charged"] == invalid[0]["reserved"] > 0
        assert budget["reserved"] == {"http": 0, "tokens": 0}
        assert manifest["llm_calls"] == len(run["provider"].requests)


def test_real_worker_admission_failure_saves_blocked_summary_without_paid_recovery(integration_run, record_testsuite_property):
    from orchestration_spec import validate_summary
    with integration_run("admission") as run:
        record_testsuite_property("full_agent_admission", str(run["directory"]))
        manifest, private, budget, tools = finished(run, "token_admission_exhausted", 2)
        assert_isolated(run, private)
        summary = read_json(private.parent / "solver/summaries/recon-1.json")
        assert summary["status"] == "blocked" and not validate_summary(summary)
        assert summary["findings"] == []
        finalization = read_json(private / "task-finalization.json")
        assert finalization["reason"] == "token_admission_exhausted"
        assert finalization["tool_artifact_count"] == 1
        assert read_json(finalization["preserved_draft"])["status"] == "in-progress"
        receipt = read_json(finalization["receipt"])
        assert receipt["security_validation_claimed"] is False
        assert len(receipt["tool_artifacts"]) == 1
        assert receipt["tool_artifacts"][0]["artifact"] == next(r["artifact"] for r in tools if r["origin"] == "solver")
        requests = read_json(private / "provider-requests.json")
        assert requests[-1]["rejection"] == "bounded_prompt_does_not_fit"
        assert requests[-1]["prompt_upper_bound"] > requests[-1]["remaining_tokens"]
        assert manifest["llm_calls"] == len(run["provider"].requests) == sum(r["admitted"] for r in requests)
        assert not budget["blocked"] and budget["reserved"] == {"http": 0, "tokens": 0}
        assert all(row["measurement_valid"] for row in budget["events"])
        assert budget["used"]["http"] == manifest["target_requests"] == 4
        assert not (private.parent / "solver/summaries/enum-2.json").exists()


@pytest.mark.parametrize("scenario", ["handoff", "handoff_bad_summary", "handoff_missing"])
def test_native_enum_real_handoff_and_access_consumption(integration_run, record_testsuite_property, scenario):
    from orchestration_spec import validate_summary
    good = scenario == "handoff"
    with integration_run(scenario) as run:
        record_testsuite_property("full_agent_" + scenario, str(run["directory"]))
        manifest, private, budget, tools = finished(run, "native_finished_unverified", 0, 3 if good else 2)
        assert_isolated(run, private)
        work = private.parent / "solver"
        gates = read_json(private / "native-gates.json")
        assert gates[0]["tool"] == "task" and gates[0]["canonical_spec_id"] == "recon-1" and gates[0]["allowed"]
        assert [g["canonical_spec_id"] for g in gates if g["tool"] == "task" and g["allowed"]] == (
            ["recon-1", "enum-2", "access-3"] if good else ["recon-1", "enum-2"])
        summary = read_json(work / "summaries/enum-2.json")
        assert summary["status"] == ("blocked" if scenario == "handoff_bad_summary" else "partial")
        assert summary["findings"] == [] and not validate_summary(summary)
        discovery = summary
        if scenario == "handoff_bad_summary":
            # Invalid assertions survive only in the private original draft;
            # the supervisor writes a valid blocked summary, never repairs
            # malformed discovery into apparent evidence or a completed step.
            discovery = read_json(private / "summary-before-stop-enum-2.json")
            assert discovery["surface"]["params"] == "invalid list shape" and validate_summary(discovery)
            assert summary["host_interruption"] and not (work / "handoff-access.json").exists()
        assert discovery["findings"] == [] and discovery["steps"][-1]["status"] == "not_tested"
        assert [r["format"] for r in discovery["surface"]["id_formats"]] == ["int", "string"]
        assert all(r["example"] == r["value"] for r in discovery["surface"]["id_formats"])
        calls = [r for r in tools if r["tool"] == "kali-tools_ledger_prepare_handoff"]
        if scenario == "handoff_missing":
            assert not calls and not (work / "handoff-access.json").exists()
        else:
            assert len(calls) == 1
            call = read_json(calls[0]["artifact"])
            result = json.loads(call["execution"]["result"]["output"])
            assert result["ok"] is good
            assert call["execution"]["actual_request_cost"] == 0
        assert budget["used"]["http"] == manifest["target_requests"] == 8
        assert not budget["blocked"] and all(e["measurement_valid"] for e in budget["events"])
        # Count only real transport tools: local ledger/PLAN tools retain their
        # ordinary invocation limits and must not be presented as wire probes.
        wire_tools = {"validator_session_vault_check": 6, "kali-tools_curl_request": 2}
        with sqlite3.connect(private / "state/audit.db") as conn:
            for tool, expected in wire_tools.items():
                # The rate table is a sliding window, not a lifetime ledger;
                # setup reservations may expire during this multi-worker run.
                decisions = [json.loads(row[0]) for row in conn.execute(
                    "SELECT metadata FROM audit_log WHERE tool_name=? AND result='allowed'", (tool,))]
                wire_decisions = [row for row in decisions if row["policy_preflight"] is False]
                assert len(wire_decisions) == expected and all(row["request_weight"] == 1 for row in wire_decisions)
                assert 0 <= conn.execute("SELECT COALESCE(SUM(weight),0) FROM rate_limit_reservations WHERE tool_name=?", (tool,)).fetchone()[0] <= expected
                assert conn.execute("SELECT COUNT(*) FROM path_probes WHERE tool_name=? AND effective=1", (tool,)).fetchone()[0] == expected
                assert conn.execute("SELECT COUNT(*) FROM stuck_probes WHERE signature LIKE ?", (tool + "|%",)).fetchone()[0] <= expected
        if good:
            assert not validate_summary(summary)
            assert result["session_references_bound"] == result["identities"] == 3
            assert result["declared_own_ids"] == 0 and result["sealed"] is False
            proof = read_json(work / "access/handoff-consumed.json")
            assert proof["pool_sha256"] == result["pool_sha256"] and proof["identity_count"] == 3
            assert proof["declared_owned_ids"] == [] and not proof["security_validation_claimed"]
            access = read_json(work / "summaries/access-3.json")
            assert access["status"] == "partial" and not validate_summary(access)
            assert access["findings"] == [] and access["steps"][-1]["status"] == "not_tested"
            plans = [r for r in tools if r["tool"] == "hunter_run_web_loop" and r["task_spec_id"] == "access-3"]
            assert len(plans) == 1
            plan_call = read_json(plans[0]["artifact"])
            plan = json.loads(plan_call["execution"]["result"]["output"])
            assert plan["ok"] and plan["mode"] == "PLAN" and plan["target"] == summary["target"]
            assert plan["plan"] and not plan["errors"] and plan["requests_authorized"] == 0
            assert plan_call["execution"]["actual_request_cost"] == 0
            assert not plan["validations"] and not plan["confirmed"]
            receipt = read_json(private / "handoff-receipts.json")["access"]
            assert receipt["producer_spec_id"] == "enum-2" and receipt["target"] == summary["target"]
            assert receipt["producer_artifact"] == calls[0]["artifact"]
            assert receipt["producer_artifact_sha256"] == preflight.sha256(Path(calls[0]["artifact"]))
            assert receipt["summary_sha256"] == call["input_summary_sha256"] == preflight.sha256(work / "summaries/enum-2.json")
            assert receipt["files"] == {str(work / name): preflight.sha256(work / name)
                                         for name in ("object-pool.json", "handoff-access.json")}
            for ident, name in (("it-handoff-read", "handoff-access.json"), ("it-pool-read", "object-pool.json")):
                requests = [row["request"] for row in run["provider"].requests if any(
                    m.get("tool_call_id") == ident for m in row["request"]["messages"])]
                assert requests and all(read_result_json(body, ident) == read_json(work / name) for body in requests)
            assert any("pool_sha256" in returned_text(row["request"], "it-handoff-read")
                       for row in run["provider"].requests if any(m.get("tool_call_id") == "it-handoff-read"
                                                                 for m in row["request"]["messages"]))
        else:
            assert not (private / "handoff-receipts.json").exists()
            assert not (work / "summaries/access-3.json").exists()
            assert not any(r["task_spec_id"] == "access-3" for r in tools)
            assert any(g["tool"] == "task" and not g["allowed"] for g in gates)
        dump(run["directory"] / "handoff-acceptance.json", {
            "scenario": scenario, "real_mcp_handoff": bool(calls), "handoff_accepted": good,
            "access_consumed": good, "negative_control_rejected": not good,
            "schema_status": "valid" if scenario != "handoff_bad_summary" else "rejected",
            "target_requests": manifest["target_requests"], "accounting_matches": True,
            "wire_policy_counts": wire_tools, "host_provenance_verified": good,
            "access_plan_completed": good, "paid_provider_calls": 0,
            "native_delegations": manifest["native_delegations"], "process_cleanup_verified": True,
            "signed_security_coverage_established": False, "full_acceptance": False})


def test_native_readonly_validation_signed_coverage(integration_run, record_testsuite_property, monkeypatch):
    from orchestration_spec import validate_summary
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    with integration_run("handoff_validation") as run:
        record_testsuite_property("full_agent_signed_validation", str(run["directory"]))
        manifest, private, budget, tools = finished(run, "native_finished_unverified", 0, delegations=4)
        assert_isolated(run, private)
        work = private.parent / "solver"
        scope = read_json(private / "scope-verification.json")
        assert scope["target"] == manifest["target"] and scope["before_traffic"]
        assert all(preflight.sha256(Path(path)) == digest for path, digest in scope["files"].items())
        gates = read_json(private / "native-gates.json")
        assert gates[0]["canonical_spec_id"] == "recon-1" and gates[0]["allowed"]
        assert [g["canonical_spec_id"] for g in gates if g["tool"] == "task" and g["allowed"]] == [
            "recon-1", "enum-2", "access-3", "report-4"]
        live = read_json(work / "access/live-result.json")
        assert live["ok"] and live["mode"] == "LIVE" and live["validations"] and live["confirmed"], live
        assert not live.get("stopped") and not live["errors"] and not live["fuzz"]["stopped"], live
        assert all(row["coverage_recorded"] for row in live["validations"])
        monkeypatch.setenv("CCO_HOME", str(private / "state"))
        signed_artifacts = []
        for row in live["validations"]:
            paths = list((private / "state/validations").glob(row["validation_id"] + "_*.json"))
            assert len(paths) == 1
            path = paths[0]
            record = read_json(path)
            assert record["verdict"] == row["verdict"] == "CONFIRMED"
            assert record["request_evidence"]
            assert artifact_is_valid(record, trusted_root=str(path.parent),
                                     expected_target=row["url"], expected_finding_type=row["vuln_class"])
            signed_artifacts.append({"path": str(path), "sha256": preflight.sha256(path),
                                     "validation_id": row["validation_id"], "public_signature_verified": True})
        assert live["requests_authorized"] > 0
        assert 8 < manifest["target_requests"] == budget["used"]["http"] <= 100
        for name in ("enum-2", "access-3", "report-4"):
            summary = read_json(work / "summaries" / (name + ".json"))
            assert summary["status"] == "partial" and not validate_summary(summary)
        assert not (work / "closure.json").exists()
        ledger = read_json(work / "report/ledger.json")
        assert ledger["coverage"]["trusted_records"] == len(live["validations"])
        assert not ledger["coverage"]["integrity_errors"] and not ledger["checkpoint"]["sealed"]
        dump(run["directory"] / "signed-access-acceptance.json", {
            "native_orchestration": True, "native_handoff_consumed": True,
            "actual_validations": live["validations"], "confirmed": live["confirmed"],
            "signed_artifacts": signed_artifacts,
            "coverage": read_json(work / "access/coverage.json"), "ledger": ledger,
            "target_requests": manifest["target_requests"], "paid_provider_calls": 0,
            "process_cleanup_verified": True, "closure_verified": False, "full_acceptance": False})


def test_native_negative_control_closure_and_tamper(integration_run, record_testsuite_property, monkeypatch):
    from orchestration_spec import validate_summary
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    with integration_run("handoff_negative") as run:
        record_testsuite_property("full_agent_negative_controls", str(run["directory"]))
        manifest, private, budget, tools = finished(run, "native_finished_unverified", 0, delegations=4)
        assert_isolated(run, private)
        work = private.parent / "solver"
        scope = read_json(private / "scope-verification.json")
        assert scope["target"] == manifest["target"] and scope["before_traffic"]
        assert all(preflight.sha256(Path(path)) == digest for path, digest in scope["files"].items())
        live = read_json(work / "access/live-result.json")
        assert live["ok"] and live["mode"] == "LIVE" and len(live["validations"]) == 1, live
        assert not live["confirmed"] and not live["errors"] and not live.get("stopped")
        assert not live["fuzz"]["stopped"]
        row = live["validations"][0]
        assert urlsplit(row["url"]).path == "/safe/go" and row["vuln_class"] == "open_redirect"
        assert row["verdict"] == "UNCONFIRMED" and row["coverage_recorded"] and row["validation_id"]
        assert any(candidate["candidate_source"] == "bounded_sampling"
                   and candidate["vuln_class"] == "open_redirect" for candidate in live["validation_candidates"])
        paths = list((private / "state/validations").glob(row["validation_id"] + "_*.json"))
        assert len(paths) == 1
        path = paths[0]
        record = read_json(path)
        monkeypatch.setenv("CCO_HOME", str(private / "state"))
        verification = {"trusted_root": str(path.parent), "expected_target": row["url"],
                        "expected_finding_type": row["vuln_class"]}
        assert record["verdict"] == "UNCONFIRMED" and record["request_evidence"]
        assert record["guard"]["transport_ok"] and artifact_is_valid(record, **verification)
        assert record["artifact"]["signature"]["algorithm"] == "ed25519:v1"
        # Change public evidence copies only; preserve the actual signed artifact.
        assert not artifact_is_valid({**record, "verdict": "CONFIRMED"}, **verification)
        invalid = {**record, "artifact": {**record["artifact"], "signature": {
            **record["artifact"]["signature"], "value": "invalid-signature"}}}
        assert not artifact_is_valid(invalid, **verification)
        coverage = read_json(work / "access/coverage.json")
        endpoint = next(item for item in coverage["per_endpoint"]
                        if urlsplit(item["endpoint"]).path == "/safe/go")
        clean = [cell for cell in endpoint["dimensions"] if cell["validation_id"] == row["validation_id"]]
        assert clean and all(cell["status"] == "tested_clean" for cell in clean)
        assert all(cell["vuln_class"] == row["vuln_class"] and cell["param"] == "next"
                   and cell["identity"] == row["identity"] for cell in clean)
        assert any(cell["status"] == "not_tested" for cell in endpoint["dimensions"])
        ledger = read_json(work / "report/ledger.json")
        checkpoint = ledger["checkpoint"]
        assert checkpoint["sealed"] is False and checkpoint["check_exit"] != 0, checkpoint
        assert "is not terminal (untried)" in checkpoint["detail"], checkpoint
        assert "closure" not in checkpoint and not (work / "closure.json").exists()
        assert ledger["coverage"]["trusted_records"] == 1 and not ledger["coverage"]["integrity_errors"]
        integrity = read_json(work / "report/negative-integrity.json")
        assert integrity["baseline"] == integrity["restored"] == ledger["coverage"]
        assert set(integrity["tampered"]) == {"verdict", "signature"}
        for kind, result in integrity["tampered"].items():
            assert result["trusted_records"] == 0 and result["integrity_errors"], (kind, result)
            expected_error = "record-hash mismatch" if kind == "verdict" else "signature mismatch"
            assert any(expected_error in error for error in result["integrity_errors"]), result
        seal_calls = [read_json(tool["artifact"]) for tool in tools
                      if tool["tool"] == "kali-tools_ledger_checkpoint"]
        assert len(seal_calls) == 1
        assert seal_calls[0]["arguments"]["seal"] is True
        for name in ("enum-2", "access-3", "report-4"):
            summary = read_json(work / "summaries" / (name + ".json"))
            assert summary["status"] == "partial" and not validate_summary(summary)
        access = read_json(work / "summaries/access-3.json")
        assert any(step["status"] == "not_tested" for step in access["steps"])
        assert 8 < manifest["target_requests"] == budget["used"]["http"] <= 100
        dump(run["directory"] / "negative-controls-acceptance.json", {
            "native_orchestration": True, "actual_validations": live["validations"],
            "signed_artifact": {"path": str(path), "sha256": preflight.sha256(path),
                                "public_signature_verified": True, "tampered_copies_rejected": True},
            "coverage": coverage, "ledger": ledger, "integrity": integrity,
            "target_requests": manifest["target_requests"], "paid_provider_calls": 0,
            "process_cleanup_verified": True, "closure_rejection_verified": True,
            "closure_verified": False, "full_acceptance": False})


def assert_successful_native_closure(integration_run, record_testsuite_property, monkeypatch,
                                    *, seed_index=0, property_name="full_agent_successful_closure"):
    import attempt_ledger as attempts
    from hypothesis_ledger import DEFAULT_VECTORS, TERMINAL
    from orchestration_spec import validate_summary
    from target_identity import canonical_target, target_key
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    with integration_run("handoff_closure", seed_index=seed_index) as run:
        record_testsuite_property(property_name, str(run["directory"]))
        manifest, private, budget, tools = finished(run, "native_finished_unverified", 0, delegations=4)
        assert_isolated(run, private)
        work = private.parent / "solver"
        scope = read_json(private / "scope-verification.json")
        assert scope["target"] == manifest["target"] and scope["before_traffic"]
        assert all(preflight.sha256(Path(path)) == digest for path, digest in scope["files"].items())
        gates = read_json(private / "native-gates.json")
        assert [g["canonical_spec_id"] for g in gates if g["tool"] == "task" and g["allowed"]] == [
            "recon-1", "enum-2", "access-3", "report-4"]
        live = read_json(work / "access/live-result.json")
        assert live["ok"] and live["mode"] == "LIVE" and live["confirmed"], live
        assert not live["errors"] and not live.get("stopped") and not live["fuzz"]["stopped"]
        row, = live["validations"]
        assert row["verdict"] == "CONFIRMED" and row["coverage_recorded"]
        assert row["vuln_class"] == "open_redirect" and urlsplit(row["url"]).path == "/go"
        paths = list((private / "state/validations").glob(row["validation_id"] + "_*.json"))
        assert len(paths) == 1
        artifact_path = paths[0]
        record = read_json(artifact_path)
        monkeypatch.setenv("CCO_HOME", str(private / "state"))
        assert record["verdict"] == "CONFIRMED" and record["request_evidence"]
        assert record["guard"]["transport_ok"]
        assert record["artifact"]["signature"]["algorithm"] == "ed25519:v1"
        assert artifact_is_valid(record, trusted_root=str(artifact_path.parent),
                                 expected_target=row["url"], expected_finding_type=row["vuln_class"])
        ledger = read_json(work / "report/ledger.json")
        checkpoint = ledger["checkpoint"]
        assert checkpoint["sealed"] is True and checkpoint["check_exit"] == 0, checkpoint
        closure_path = work / "closure.json"
        assert checkpoint["closure"] == str(closure_path) and closure_path.is_file()
        signed = read_json(closure_path)
        assert signed["signature_alg"] == "ed25519:v1"
        payload, reason = attempts.verify_signed_payload(signed)
        assert payload is not None and not reason
        assert payload["producer"] == "gate" and payload["schema"] == "closure/2"
        assert payload["workdir"] == str(work.resolve())
        assert payload["target"] == canonical_target(manifest["target"])
        assert payload["target_key"] == target_key(manifest["target"])
        assert {entry["vector"] for entry in payload["hypotheses"]} == set(DEFAULT_VECTORS)
        assert all(entry["status"] in TERMINAL for entry in payload["hypotheses"])
        confirmed, = [entry for entry in payload["hypotheses"] if entry["status"] == "confirmed"]
        assert confirmed["vector"] == "authn-session"
        validation, = payload["validations"]
        assert validation["vector"] == "authn-session" and validation["validation_id"] == row["validation_id"]
        assert validation["validation_sha256"] == record["artifact"]["content_sha256"]
        assert all(record["binding"][key] == value for key, value in payload["binding"].items())
        assert {entry["vector"] for entry in payload["not_tested"]} == set(DEFAULT_VECTORS) - {"authn-session"}
        assert all(entry["justification"].startswith("auth:not-required:") for entry in payload["not_tested"])
        records = attempts.read_records(work / "attempts.jsonl")
        trusted, errors = attempts.verify_records(records, path=work / "attempts.jsonl")
        assert not errors and len(trusted) == len(records) == 1
        assert trusted[0]["vector"] == "authn-session" and trusted[0]["note"] == row["validation_id"]
        assert payload["ledger"]["records"] == payload["ledger"]["trusted"] == 1
        assert payload["ledger"]["sig_errors"] == payload["ledger"]["chain_errors"] == 0
        integrity = read_json(work / "report/closure-integrity.json")
        assert integrity["source"] == "native_bash_cli_with_pinned_public_trust"
        assert integrity["baseline"]["exit_code"] == integrity["restored"]["exit_code"] == 0
        assert "closure verify: verified" in integrity["baseline"]["stdout"]
        assert integrity["original_bytes_restored"]
        assert set(integrity["tampered"]) == {
            "closure_payload", "closure_signature", "attempt_verdict", "attempt_signature", "attempt_removed"}
        for outcome in integrity["tampered"].values():
            assert outcome["exit_code"] == 2 and "closure verify:" in outcome["stdout"]
            assert outcome["restored"]["exit_code"] == 0
        seal_calls = [read_json(tool["artifact"]) for tool in tools
                      if tool["tool"] == "kali-tools_ledger_checkpoint"]
        assert len(seal_calls) == 1 and seal_calls[0]["arguments"]["seal"] is True
        assert sum(g["tool"] == "bash" and g["allowed"] for g in gates) >= 3
        for name in ("enum-2", "access-3", "report-4"):
            summary = read_json(work / "summaries" / (name + ".json"))
            assert summary["status"] == "partial" and not validate_summary(summary)
        assert 8 < manifest["target_requests"] == budget["used"]["http"] <= 100
        dump(run["directory"] / "closure-acceptance.json", {
            "native_orchestration": True, "actual_validations": live["validations"],
            "signed_artifact": {"path": str(artifact_path), "sha256": preflight.sha256(artifact_path),
                                "public_signature_verified": True},
            "closure": {"path": str(closure_path), "sha256": preflight.sha256(closure_path),
                        "public_signature_verified": True, "payload": payload},
            "ledger": ledger, "integrity": integrity,
            "target_requests": manifest["target_requests"], "paid_provider_calls": 0,
            "process_cleanup_verified": True, "closure_verified": True, "full_acceptance": False})
        return {"directory": run["directory"], "manifest": manifest, "private": private,
                "workdir": work, "signed_closure": signed, "previous_runs": run["previous_runs"],
                "isolation": read_json(work / "isolation-proof.json")}


def test_native_successful_closure_and_integrity(integration_run, record_testsuite_property, monkeypatch):
    assert_successful_native_closure(integration_run, record_testsuite_property, monkeypatch)


def test_native_holdout_seed_isolation_and_signed_closure(integration_run, record_testsuite_property, monkeypatch):
    """Two frozen comparison seeds prove isolation, not independent-family recall."""
    import attempt_ledger as attempts
    monkeypatch.syspath_prepend(str(ROOT / "mcp-servers/mcp-validator"))
    from cco_validator_core.evidence import artifact_is_valid

    baseline = assert_successful_native_closure(integration_run, record_testsuite_property, monkeypatch,
        seed_index=0, property_name="full_agent_seed_baseline")
    first = baseline["manifest"]
    previous_root = baseline["private"].parent
    public_paths = [path for path in baseline["workdir"].rglob("*") if path.is_file()]
    public_paths.extend((baseline["private"] / "state/validations").glob("*.json"))
    previous_hashes = {str(path): preflight.sha256(path) for path in public_paths}
    prior_records = attempts.read_records(baseline["workdir"] / "attempts.jsonl")
    prior_validation = read_json(next((baseline["private"] / "state/validations").glob("*.json")))

    held_out = assert_successful_native_closure(integration_run, record_testsuite_property, monkeypatch,
        seed_index=1, property_name="full_agent_held_out_seed")
    second = held_out["manifest"]
    assert first["seed"] != second["seed"]
    assert baseline["workdir"] != held_out["workdir"]
    assert baseline["private"] != held_out["private"]
    assert previous_root in held_out["previous_runs"]
    assert set(first["native_session_ids"]).isdisjoint(second["native_session_ids"])
    assert baseline["signed_closure"]["key_id"] != held_out["signed_closure"]["key_id"]
    for run in (baseline, held_out):
        manifest = run["manifest"]
        contract = read_json(Path(manifest["preflight"]).parent / "contract.json")
        assert manifest["seed"] in contract["baseline"]["seeds"]
        assert contract["holdout"]["minimum_families"] == 3
        assert contract["holdout"]["seed_variation_is_independent_family"] is False
        assert contract["holdout"]["status"] == manifest["holdout"] == "not_evaluated"
        assert manifest["acceptance_passed"] is False
    observed = [read_json(run["workdir"] / "summaries/enum-2.json")["surface"]["routes"]
                for run in (baseline, held_out)]
    # This lab's anonymous entry links are shared across seeds. Fresh seed
    # selection is a launcher fact, not evidence of a new holdout family.
    assert set(observed[0]) == set(observed[1])
    current_validation = read_json(next((held_out["private"] / "state/validations").glob("*.json")))
    assert prior_validation["validation_id"] != current_validation["validation_id"]
    assert prior_validation["artifact"]["content_sha256"] != current_validation["artifact"]["content_sha256"]
    for name in ("closure.json", "attempts.jsonl", "hypotheses.json", "object-pool.json",
                 "summaries/access-3.json", "access/live-result.json", "report/closure-integrity.json"):
        assert str(baseline["workdir"] / name) in held_out["isolation"]["denied"]
    assert all(preflight.sha256(Path(path)) == digest for path, digest in previous_hashes.items())
    # Verification under the new run's actual public key must reject replay.
    # Original evidence remains valid under its original trust bundle.
    payload, reason = attempts.verify_signed_payload(baseline["signed_closure"])
    assert payload is None and reason == "signature mismatch"
    trusted, errors = attempts.verify_records(prior_records, path=baseline["workdir"] / "attempts.jsonl")
    assert not trusted and any("signature mismatch" in error for error in errors)
    assert not artifact_is_valid(prior_validation)
    with monkeypatch.context() as original_trust:
        original_trust.setenv("CCO_HOME", str(baseline["private"] / "state"))
        assert attempts.verify_signed_payload(baseline["signed_closure"])[0] is not None
        assert not attempts.verify_records(prior_records, path=baseline["workdir"] / "attempts.jsonl")[1]
        assert artifact_is_valid(prior_validation)
    dump(held_out["directory"] / "held-out-seed-acceptance.json", {
        "native_orchestration": True, "seeds": [first["seed"], second["seed"]],
        "runs": [{"directory": str(run["directory"]), "workdir": str(run["workdir"]),
                  "seed": run["manifest"]["seed"], "native_session_ids": run["manifest"]["native_session_ids"],
                  "key_id": run["signed_closure"]["key_id"], "closure_verified": True,
                  "target_requests": run["manifest"]["target_requests"]} for run in (baseline, held_out)],
        "fresh_sessions_verified": True, "prior_results_unreadable": True,
        "prior_result_sha256": previous_hashes, "prior_results_unchanged": True,
        "cross_run_signature_replay_rejected": True, "original_trust_verification_passed": True,
        "comparison_surface": "same_family_anonymous_links", "fresh_validation_evidence": True,
        "process_cleanup_verified": True,
        "paid_provider_calls": 0, "seed_isolation_verified": True,
        "independent_family_holdout": "not_evaluated", "full_acceptance": False})


def integration_child():
    """CLI adapter: configure lab responses, never a process or transport double.

    The original lab handles every ordinary request. One test-only path waits
    for shutdown so an actual host MCP executor is alive when SIGINT/deadline
    fires. It spawns no substitute MCP or solver implementation.
    """
    scenario = os.environ["INTEGRATION_SCENARIO"]
    if scenario == "handoff_negative":
        # Test-fixture configuration only (not a production budget increase):
        # host_environment rebuilds the child env from an allowlist, so the
        # finite-corpus repeat threshold from integration_run would be
        # dropped before the policy gate runs. Re-apply the same small
        # finite value (32) inside that context for this scenario only.
        _host_environment = launcher.host_environment

        @contextmanager
        def _handoff_negative_environment(*args, **kwargs):
            with _host_environment(*args, **kwargs):
                os.environ["CCO_STUCK_THRESHOLD"] = "32"
                yield

        launcher.host_environment = _handoff_negative_environment
    if scenario in {"handoff_validation", "handoff_negative", "handoff_closure"}:
        from lab import blind_lab
        original = blind_lab.serve

        def serve(*args, **kwargs):
            server = original(*args, **kwargs)
            handler, state = server.RequestHandlerClass, server.blind_state

            class ValidationHandler(handler):
                def do_GET(self):
                    parsed = urlsplit(self.path)
                    destination = parse_qs(parsed.query, keep_blank_values=True).get("next", [""])[0]
                    route = "/safe/go" if scenario == "handoff_negative" else "/go"
                    if parsed.path == route and not urlsplit(destination).netloc:
                        # Keep discovery on this observed parameterized page.
                        # Discovery stores an empty parameter placeholder, so
                        # it also needs a usable, non-redirecting baseline.
                        # The original handler supplies actual 302 Location
                        # responses on /go and rejects them on /safe/go.
                        with state["lock"]:
                            state["requests"] += 1
                        return self._send(200, "<html>Continue to the selected destination</html>")
                    return super().do_GET()

            server.RequestHandlerClass = ValidationHandler
            return server

        blind_lab.serve = serve
    elif scenario in {"timeout", "sigint"}:
        from lab import blind_lab
        original = blind_lab.serve
        output = Path(os.environ["INTEGRATION_OUTPUT"])

        def serve(*args, **kwargs):
            server = original(*args, **kwargs)
            handler = server.RequestHandlerClass

            class DelayedHandler(handler):
                def do_GET(self):
                    if self.path == "/__integration_wait__":
                        dump(output / "host-blocked.json", {"received": True})
                        # Longer than both CLI deadlines; no request completion
                        # can race the shutdown assertion or refund HTTP usage.
                        threading.Event().wait(180)
                        return
                    return super().do_GET()

            server.RequestHandlerClass = DelayedHandler
            return server

        blind_lab.serve = serve
    return launcher.main(sys.argv[2:])


if __name__ == "__main__":
    if sys.argv[1:2] != ["--integration-child"]:
        raise SystemExit("Use pytest to run this integration suite")
    raise SystemExit(integration_child())
