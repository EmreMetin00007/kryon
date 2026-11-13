"""Private host mediator: native MCP, policy checks and one metered provider.

Only this process owns target sessions, provider credentials and signing keys.
The solver can reach it through one mounted Unix socket, never the host network.
"""
from __future__ import annotations

import asyncio
import hashlib
from http.client import HTTPException
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
from socketserver import ThreadingMixIn, UnixStreamServer
import tempfile
import threading
import time

from full_agent_budget import (BudgetError, compact_json_text, compact_tools, completion_request,
                               prompt_bound, provider_accounting_usage, provider_json, usage_tokens)

MAX_BODY = 16 * 1024 * 1024
# Native Commands carry tool guidance; keep narrative metadata small without
# changing names, argument schemas, literals or the admission bound.
NATIVE_DESCRIPTION_LIMIT = 20
# Reviewed entry points only. No arbitrary shell, raw database, credentials,
# external scanners or MCP-internal paid model calls cross this boundary.
CATALOG = {
    "hunter": {"run_web_loop", "fuzz_attack_surface", "coverage_report", "predict_vulnerabilities"},
    "validator": {"validate_sqli", "validate_ssti", "validate_path_traversal", "validate_xss_reflection",
                  "validate_open_redirect", "validate_auth_bypass", "validate_idor", "session_vault_check"},
    "browser": {"browser_extract_links", "browser_capture_requests", "browser_runtime_observe",
                "browser_dom_xss_probe"},
    "kali-tools": {"curl_request", "crawl_web_surface", "compose_js_routes", "ledger_attempt_add",
                   "ledger_attempt_add_batch", "ledger_coverage", "ledger_prepare_handoff", "ledger_checkpoint"},
    "reasoning": {"recall_lessons", "record_lesson"},
}
LOCAL_TOOLS = {"read", "glob", "grep", "list", "skill", "todowrite", "task", "bash", "write", "edit", "apply_patch"}


def dump(path, value):
    path = Path(path)
    content = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".native-", delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(content)
            handle.flush()
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def runtime_request(body, info, *, native_context):
    """Append exactly the allowance text included in provider admission."""
    instruction = (' Submit submit_phase_summary from existing evidence; preserve NOT TESTED work.'
                   if not native_context else
                   ' FINALIZE NOW: save a terminal summary from existing evidence. '
                   'Keep remaining work NOT TESTED; do not repeat probes. Finish the current '
                   'handoff/ledger/closure only through the available host tools. Return after saving.'
                   if info['finalizing'] else
                   ' Complete Commands within this allowance; save the terminal summary and '
                   'required handoff before running out. Do not record recon in the attempt ledger.')
    return {**body, 'messages': [*body['messages'], {'role': 'user',
        'content': 'Host runtime allowance: ' + provider_json(info).decode() + instruction}]}


def provider_usage_diagnostics(response):
    """Retain bounded accounting shape, never model text or arbitrary values."""
    def count(value):
        result = {'type': type(value).__name__ if type(value) in {
            int, float, bool, str, list, dict, type(None)} else 'other'}
        if type(value) is int and abs(value) <= 1_000_000_000_000:
            result['value'] = value
        return result

    if not isinstance(response, dict):
        return {'response_object': False}
    usage = response.get('usage')
    result = {'response_object': True, 'usage_present': 'usage' in response,
              'usage_type': count(usage)['type'], 'error_present': 'error' in response,
              'choices_count': min(len(response['choices']), 1000)
                  if isinstance(response.get('choices'), list) else None}
    if isinstance(usage, dict):
        result['counts'] = {key: count(usage[key]) for key in (
            'prompt_tokens', 'completion_tokens', 'total_tokens') if key in usage}
        result['details'] = {}
        for field, subset in (('prompt_tokens_details', 'cached_tokens'),
                              ('completion_tokens_details', 'reasoning_tokens')):
            if field in usage:
                detail = usage[field]
                result['details'][field] = {'type': count(detail)['type']}
                if isinstance(detail, dict) and subset in detail:
                    result['details'][field][subset] = count(detail[subset])
    return result


def provider_failure_reason(exc, status):
    """Classify known host errors without persisting exception text."""
    if status is not None and status != 200:
        return 'provider_http_error'
    if isinstance(exc, BudgetError):
        if exc.code is not None:
            return exc.code
        return {
            'provider omitted usage': 'usage_missing',
            'invalid provider token usage': 'usage_counts_invalid',
            'inconsistent provider token usage': 'usage_total_inconsistent',
            'invalid provider usage details': 'usage_details_invalid',
            'invalid provider usage subset': 'usage_subset_invalid',
            'provider usage exceeded admitted prompt or output bound': 'usage_bound_exceeded',
            'provider response omitted choices': 'choices_missing',
            'provider response too large': 'response_too_large',
            'native session is closed': 'session_closed',
        }.get(str(exc), 'provider_budget_error')
    if isinstance(exc, (json.JSONDecodeError, UnicodeDecodeError)):
        return 'response_json_invalid'
    # raw.read() can raise urllib3/http.client errors directly, outside
    # requests' exception wrapper, even after receiving HTTP 200 headers.
    from requests.exceptions import RequestException
    from urllib3.exceptions import HTTPError
    if isinstance(exc, (RequestException, HTTPError, HTTPException, OSError)):
        return 'provider_transport_error'
    return 'provider_response_invalid'


def provider_failure(reason, status, *, reservation_retained):
    """Surface a stable diagnosis without upstream exception/body text."""
    message = (f"provider HTTP {status}; response body withheld" if reason == 'provider_http_error'
               else reason.replace('_', ' '))
    if reservation_retained:
        message += '; token reservation retained'
    return BudgetError(message, code=reason)


class Broker:
    def __init__(self, *, budget, engine, executor, workdir, private, provider, models, api_key,
                 api_key_header="Authorization", tasks=None):
        if api_key_header not in {"Authorization", "X-API-Key"}:
            raise ValueError("unsupported provider API key header")
        self.budget, self.engine, self.executor = budget, engine, executor
        self.workdir, self.private = Path(workdir).resolve(), Path(private)
        self.provider, self.models, self.api_key = provider, set(models), api_key
        self.api_key_header = api_key_header
        self.tasks = tasks
        self.lock = threading.RLock()
        self.provider_lock = threading.Lock()
        self.transport_lock = threading.Lock()
        self.closed = threading.Event()
        self.upstream = None
        self.nonce, self.ready = secrets.token_hex(24), False
        self.catalog = {}
        self.tools = []
        self.gates = []
        self.loops = []
        self.checkpoints = []
        self.calls = 0
        self.provider_requests = []
        self.provider_responses = []
        self.stop_reason = ""
        self.task_finalization = None
        self.handoffs = {}
        self.task_calls = {}
        self.completed_tasks = []
        self.runtime_policy = None

    def close(self):
        """Stop admission before terminating host tool children and provider IO."""
        self.closed.set()
        self.executor.terminate()
        # A call may have been admitted just before the stop. Wait for its
        # short cleanup, then terminate again to cover a concurrent spawn.
        if self.lock.acquire(timeout=5):
            try:
                self.executor.terminate()
            finally:
                self.lock.release()
        with self.transport_lock:
            upstream, self.upstream = self.upstream, None
        if upstream is not None:
            # Closing a response while another thread reads it can block on
            # the IO lock. It must never delay killing the native process tree.
            def close_response():
                try:
                    upstream.close()
                except Exception:
                    pass
            closer = threading.Thread(target=close_response, daemon=True)
            closer.start()
            closer.join(timeout=0.2)

    def _require_open(self):
        if self.closed.is_set():
            raise BudgetError("native session is closed")
        if self.stop_reason:
            raise BudgetError(self.stop_reason)

    def finalize_task(self, reason):
        """Called only after the native process tree has exited; no model call."""
        with self.lock:
            if self.task_finalization is not None or self.tasks is None or self.tasks.active_spec is None:
                return self.task_finalization
            spec = self.tasks.active_spec
            try:
                evidence = []
                for row in self.tools:
                    if row.get("task_spec_id") != spec.id or row["origin"] != "solver":
                        continue
                    path = Path(row["artifact"])
                    evidence.append({"tool": row["tool"], "artifact": str(path),
                                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
                self.task_finalization = self.tasks.finalize_active(reason, evidence, self.private)
            except (ValueError, OSError) as exc:
                # Malicious/unreadable paths must not prevent process cleanup
                # or cause an unsafe write. Never retain exception text.
                self.task_finalization = {"spec_id": spec.id, "reason": reason,
                                          "action": "summary_preserved", "error": type(exc).__name__}
            dump(self.private / "task-finalization.json", self.task_finalization)
            return self.task_finalization

    def load_catalog(self, home):
        from campaign_worker import _load_server_module
        for group, allowed in CATALOG.items():
            mod = _load_server_module("mcp-" + group, home)
            rows = asyncio.run(mod.mcp.list_tools())
            # This mediator emits text content, not FastMCP structuredContent.
            # Advertising the original outputSchema makes native clients
            # compile/enforce a response contract this transport does not use.
            self.catalog[group] = compact_tools([
                row.model_dump(mode="json", exclude_none=True, exclude={"outputSchema"})
                for row in rows if row.name in allowed], description_limit=NATIVE_DESCRIPTION_LIMIT)
            found = {row["name"] for row in self.catalog[group]}
            if found != allowed:
                raise ValueError("native MCP catalog mismatch: " + group + " " + str(sorted(allowed - found)))

    def _handoff_file_hash(self, path):
        raw = Path(path)
        resolved = raw.resolve(strict=True)
        if (raw.is_symlink() or resolved.parent != self.workdir or not resolved.is_file()
                or resolved.stat().st_size > 1024 * 1024):
            raise ValueError("handoff file must be a bounded regular workdir file")
        return hashlib.sha256(resolved.read_bytes()).hexdigest()

    def _remember_handoff(self, args, result, artifact, summary_hash):
        """Record only output from a successful host MCP execution, not prose."""
        if self.tasks is None or not isinstance(result, dict) or result.get("ok") is not True:
            return
        source = self.tasks.active_spec
        if source is None or source.phase not in {"enum", "seed"} or args.get("target") != source.target:
            raise ValueError("handoff producer does not match the active discovery task")
        summary = self.tasks.summary_path(source)
        supplied = self.workdir / args.get("summary_file", "summaries/enum-2.json")
        if supplied.resolve() != summary:
            raise ValueError("handoff must consume the active discovery summary")
        if hashlib.sha256(summary.read_bytes()).hexdigest() != summary_hash:
            raise ValueError("discovery summary changed during handoff preparation")
        pool = self.workdir / "object-pool.json"
        pending = {}
        for label, name in result.get("handoffs", {}).items():
            path = self.workdir / ("handoff-" + label + ".json")
            if str(path) != name or path.parent != self.workdir:
                raise ValueError("unexpected host handoff path")
            pending[label] = {"producer_spec_id": source.id, "target": source.target,
                "summary": str(summary), "summary_sha256": summary_hash,
                "producer_artifact": str(artifact), "producer_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                "files": {str(pool): self._handoff_file_hash(pool), str(path): self._handoff_file_hash(path)}}
        self.handoffs.update(pending)
        dump(self.private / "handoff-receipts.json", self.handoffs)

    def _check_handoff(self, spec):
        if spec.phase not in {"access", "authz"}:
            return
        label = spec.vector or spec.phase
        record = self.handoffs.get(label)
        if not record or record["target"] != spec.target:
            raise ValueError("host handoff missing for " + spec.id)
        source = next(s for s in self.tasks.specs if s.id == record["producer_spec_id"])
        summary = self.tasks.summary_path(source)
        if hashlib.sha256(summary.read_bytes()).hexdigest() != record["summary_sha256"]:
            raise ValueError("host handoff stale: discovery summary changed")
        if any(self._handoff_file_hash(path) != digest for path, digest in record["files"].items()):
            raise ValueError("host handoff stale: packet or pool changed")
        from brain import _handoff_gate_error
        error = _handoff_gate_error(spec)
        if error:
            raise ValueError(error)

    def gate(self, body):
        self._require_open()
        tool, args = body.get("tool"), body.get("args") or {}
        if not isinstance(tool, str) or not isinstance(args, dict):
            raise ValueError("invalid native gate call")
        named = {group + "_" + name for group, names in CATALOG.items() for name in names}
        with self.lock:
            spec = None
            policy_denial = None
            if (self.runtime_policy is not None and self.tasks.active_spec is not None
                    and tool in LOCAL_TOOLS - {"task"}):
                try:
                    self.runtime_policy.check_tool(self.tasks.active_spec, tool)
                except ValueError as exc:
                    policy_denial = str(exc)
                except BudgetError as exc:
                    self.stop_reason = str(exc)
                    raise
            if policy_denial:
                decision = {"allowed": False, "reason": policy_denial}
            elif tool not in LOCAL_TOOLS | named:
                decision = {"allowed": False, "reason": "tool outside benchmark catalog"}
            elif (tool in named and self.tasks is not None and self.tasks.active_spec is not None
                  and tool not in self.tasks.active_spec.tools):
                decision = {"allowed": False, "reason": "tool outside active TaskSpec"}
            elif tool in named:
                # This native hook cannot execute an MCP tool. Its only route
                # is call_tool below, which checks the current host policy.
                # Do not count a second invocation at the dispatch-only hook.
                decision = {"allowed": True, "reason": "host_policy_at_execution"}
            elif tool == "task" and args.get("subagent_type") != "worker":
                decision = {"allowed": False, "reason": "only native worker delegation is allowed"}
            else:
                try:
                    if tool == "task" and self.tasks is not None:
                        spec, args = self.tasks.resolve(args)
                        self._check_handoff(spec)
                    decision = self.engine.validate_tool_invocation(tool, args)
                    if decision["allowed"] and spec is not None:
                        self.tasks.scaffold(spec, prompt=args['prompt'])
                        key = (body.get('session_id'), body.get('call_id'))
                        self.task_calls[key] = {'spec_id': spec.id, 'args': json.loads(json.dumps(args))}
                except (ValueError, OSError) as exc:
                    decision = {"allowed": False, "reason": str(exc)[:300]}
            self.gates.append({"tool": tool, "session_id": body.get("session_id"),
                               "call_id": body.get("call_id"), "allowed": decision["allowed"],
                               "canonical_spec_id": spec.id if spec is not None else None,
                               "reason": decision.get("reason", "")})
            if self.runtime_policy is not None and tool in LOCAL_TOOLS - {'task'} and self.tasks.active_spec:
                self.runtime_policy.record_result(self.tasks.active_spec, tool,
                    {'execution_failed': not decision['allowed'],
                     'result': {'output': {'ok': decision['allowed']}}})
            dump(self.private / "native-gates.json", self.gates)
            if self.tasks is not None:
                dump(self.private / "summary-normalizations.json", self.tasks.normalizations)
        result = {"allowed": decision["allowed"], "reason": decision.get("reason", "")}
        if decision["allowed"] and spec is not None:
            result["args"] = args
        return result

    def record_task_completion(self, body):
        """Native after-hook receipt; context only, never execution authority."""
        from full_agent_context import terminal_summary, verified_file
        if (not isinstance(body, dict) or set(body) != {'tool', 'session_id', 'call_id', 'output', 'metadata'}
                or body['tool'] != 'task' or not isinstance(body['session_id'], str)
                or not isinstance(body['call_id'], str) or not isinstance(body['output'], str)
                or len(body['output'].encode()) > 64 * 1024 or not isinstance(body['metadata'], dict)
                or set(body['metadata']) != {'parentSessionId', 'sessionId'}):
            return {'recorded': False, 'reason': 'unsupported_completion_shape'}
        with self.lock:
            self._require_open()
            call = self.task_calls.get((body['session_id'], body['call_id']))
            if call is None or self.tasks is None:
                return {'recorded': False, 'reason': 'missing_admission'}
            metadata = body['metadata']
            child = metadata['sessionId']
            if (metadata['parentSessionId'] != body['session_id'] or not isinstance(child, str) or not child
                    or not body['output'].startswith(f'<task id="{child}" state="completed">\n<task_result>\n')
                    or not body['output'].endswith('\n</task_result>\n</task>')):
                return {'recorded': False, 'reason': 'native_completion_mismatch'}
            spec = next(s for s in self.tasks.specs if s.id == call['spec_id'])
            summary = terminal_summary(self.tasks, spec)
            contract = verified_file(self.workdir, str(Path(spec.evidence_dir) / 'task-context.txt'),
                                     call['args']['prompt'].encode())
            if summary is None or contract is None:
                return {'recorded': False, 'reason': 'unverified_summary_or_contract'}
            receipt = {'schema': 'native-task-completion/1', 'spec_id': spec.id,
                       'call_id': body['call_id'], 'session_id': body['session_id'],
                       'args': call['args'], 'output': body['output'], 'metadata': metadata,
                       'summary': summary[1], 'summary_status': summary[0]['status'], 'contract': contract,
                       'security_validation_claimed': False}
            raw = provider_json(receipt)
            if len(raw) > 128 * 1024:
                return {'recorded': False, 'reason': 'receipt_too_large'}
            sha = hashlib.sha256(raw).hexdigest()
            path = self.private / ('task-completion-' + sha + '.json')
            if not path.exists():
                with path.open('xb') as handle:
                    handle.write(raw)
            elif path.is_symlink() or path.read_bytes() != raw:
                return {'recorded': False, 'reason': 'receipt_changed'}
            record = {'artifact': str(path), 'sha256': sha}
            if record not in self.completed_tasks:
                self.completed_tasks.append(record)
                dump(self.private / 'task-completions.json', self.completed_tasks)
            return {'recorded': True, 'sha256': sha}

    def _confine(self, args):
        # Ledger calls read solver-authored files on the host. Require their
        # standard confinement checks, and disallow links out of the mount.
        for name in ("workdir", "artifact", "summary_file", "spec_file"):
            value = args.get(name)
            if value:
                if not isinstance(value, str):
                    raise ValueError("invalid artifact path")
                path = (self.workdir / value).resolve()
                if path != self.workdir and self.workdir not in path.parents:
                    raise ValueError("artifact path escapes solver workspace")

    def call_tool(self, group, name, args, *, origin="solver"):
        if name not in CATALOG.get(group, set()) or not isinstance(args, dict):
            raise ValueError("tool outside benchmark catalog")
        full = group + "_" + name
        with self.lock:  # One active MCP call; nested browser requests share its allowance.
            self._require_open()
            if (origin == "solver" and self.tasks is not None and self.tasks.active_spec is not None
                    and full not in self.tasks.active_spec.tools):
                raise ValueError("tool outside active TaskSpec")
            if origin == "solver" and self.runtime_policy is not None and self.tasks.active_spec is not None:
                try:
                    self.runtime_policy.check_tool(self.tasks.active_spec, full)
                except BudgetError as exc:
                    self.stop_reason = str(exc)
                    raise
            self._confine(args)
            summary_hash = None
            if full == "kali-tools_ledger_prepare_handoff" and self.tasks is not None:
                summary_path = self.workdir / args.get("summary_file", "summaries/enum-2.json")
                self.tasks.normalize_summary_file(summary_path)
                summary_hash = hashlib.sha256(summary_path.read_bytes()).hexdigest()
                dump(self.private / "summary-normalizations.json", self.tasks.normalizations)
            from wire_budget import network_required, require_accounted_tool
            require_accounted_tool(full, args, self.engine)
            network = network_required(full, args, self.engine)
            # Every supported network adapter rechecks the actual request at
            # egress. This outer shape/scope/grant check must not consume its
            # stuck/rate counters before that same request is sent.
            decision = self.engine.validate_tool_invocation(full, args, _policy_preflight=True) if network else self.engine.validate_tool_invocation(full, args)
            if not decision["allowed"]:
                raise ValueError("policy denied: " + decision.get("reason", ""))
            reservation = self.budget.available("http") if network else 0
            if network and reservation == 0:
                raise BudgetError("http budget exhausted")
            ticket = self.budget.reserve("http", reservation)
            dump(self.private / "budget.json", self.budget.snapshot())
            self.executor.timeout_seconds = min(900, self.budget.remaining_seconds())
            result, error = None, None
            artifact = self.private / f"tool-{len(self.tools):04d}.json"
            spec_id = self.tasks.active_spec.id if origin == "solver" and self.tasks is not None and self.tasks.active_spec else None
            try:
                self._require_open()
                result = self.executor({"tool_name": full, "args_json": json.dumps(args),
                                        "request_cost": reservation, "reserved_request_cost": reservation})
            except BaseException as exc:
                error = type(exc).__name__
                raise
            finally:
                if self.runtime_policy is not None and spec_id is not None:
                    self.runtime_policy.record_result(self.tasks.active_spec, full, result, error)
                # LocalMCPExecutor validates the random invocation ID and wire
                # reservation. An interrupted child is charged its full allowance.
                try:
                    self.budget.settle(ticket, result.get("actual_request_cost") if isinstance(result, dict) else None,
                                       tool=full, origin=origin)
                finally:
                    dump(self.private / "budget.json", self.budget.snapshot())
                    dump(artifact, {"tool": full, "arguments": args, "execution": result,
                                    "origin": origin, "error": error, "task_spec_id": spec_id,
                                    "input_summary_sha256": summary_hash})
                    self.tools.append({"tool": full, "artifact": str(artifact), "origin": origin,
                                       "task_spec_id": spec_id})
            raw = result["result"].get("output")
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
            except ValueError:
                parsed = None
            if full == "hunter_run_web_loop" and isinstance(parsed, dict) and parsed.get("run_id"):
                self.loops.append(parsed)
            if full == "kali-tools_ledger_prepare_handoff" and not result.get("execution_failed"):
                self._remember_handoff(args, parsed, artifact, summary_hash)
            if full == "kali-tools_ledger_checkpoint":
                self.checkpoints.append({"args": args, "output": parsed})
            return {"content": [{"type": "text", "text": compact_json_text(raw) if isinstance(raw, str)
                                 else provider_json(raw).decode("utf-8")}],
                    "isError": bool(result.get("execution_failed"))}

    def project_runtime_context(self, body, spec, info):
        return body, info, None

    def completion(self, body, *, native_context=True):
        with self.provider_lock:
            self._require_open()
            if isinstance(body, dict) and "tools" in body:
                body = {**body, "tools": compact_tools(body["tools"], description_limit=NATIVE_DESCRIPTION_LIMIT,
                                                       strip_annotations=True)}
            active = self.tasks.active_spec if self.tasks is not None else None
            tools = body.get("tools") if isinstance(body, dict) else None
            worker_call = isinstance(tools, list) and bool(tools) and not any(
                row.get("function", {}).get("name") == "task" for row in tools)
            if active is not None and worker_call and native_context:
                allowed = (self.runtime_policy.allowed_tools(active) if self.runtime_policy is not None
                           else set(active.tools) | {"read", "write", "edit", "bash"})
                body["tools"] = [row for row in tools if row.get("function", {}).get("name") in allowed]
                for row in body['tools']:
                    function = row.get('function', {})
                    if function.get('name') == 'kali-tools_ledger_prepare_handoff':
                        # These are opaque host-owned references, not session
                        # status summaries. Give the model the exact accepted
                        # literal; execution still independently validates it.
                        parameters = function.setdefault('parameters', {'type': 'object'})
                        properties = parameters.setdefault('properties', {})
                        properties['session_bindings_json'] = {
                            'type': 'string', 'enum': [provider_json(self.tasks.bindings).decode()],
                            'description': 'Use this exact host binding literal; do not add status fields.'}
                        required = parameters.setdefault('required', [])
                        if 'session_bindings_json' not in required:
                            required.append('session_bindings_json')
                from full_agent_context import worker_followup_context
                body, context = worker_followup_context(body, self.tasks, self.private, self.tools, self.handoffs)
            else:
                context = None
                if native_context and self.tasks is not None and isinstance(tools, list) and any(
                        row.get('function', {}).get('name') == 'task' for row in tools):
                    from full_agent_context import planner_followup_context
                    body, context = planner_followup_context(body, self.tasks, self.private, self.completed_tasks)
            remaining = self.budget.available("tokens")
            metrics = {"remaining_tokens": remaining,
                       "messages_bytes": len(provider_json(body.get("messages"))) if isinstance(body, dict) else 0,
                       "tools_bytes": len(provider_json(body.get("tools"))) if isinstance(body, dict) else 0,
                       "admitted": False, "task_spec_id": active.id if active is not None and worker_call else None}
            if context is not None:
                metrics['context_projection'] = context
            self.provider_requests.append(metrics)
            runtime_info = None
            try:
                if self.runtime_policy is not None:
                    from full_agent_history import bounded_history
                    from full_agent_runtime_policy import (MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS,
                                                          MIN_OUTPUT_TOKENS)
                    if worker_call and native_context:
                        for recent in (2, 1, 0):
                            too_big = (len(provider_json(body['messages'])) > MAX_CONTEXT_BYTES
                                       or prompt_bound(provider_json(body))[0] > MAX_PROMPT_TOKENS)
                            if not too_big:
                                break
                            body, archived = bounded_history(body, self.tasks,
                                max_bytes=min(MAX_CONTEXT_BYTES, len(provider_json(body['messages'])) - 1),
                                recent_turns=recent, compact=True)
                            if archived is not None:
                                metrics.setdefault('history_projections', []).append(archived)
                    if worker_call and not native_context:
                        # A discarded oversized context must not permanently
                        # close a phase that fits after bounded projection.
                        body, runtime_info, projection = self.project_runtime_context(body, active, None)
                        if projection is not None:
                            metrics['context_projection'] = projection
                    else:
                        runtime_info = self.runtime_policy.prepare(active if worker_call else None,
                                                                   prompt_bound(provider_json(body))[0])
                    if worker_call and native_context:
                        allowed = self.runtime_policy.allowed_tools(active)
                        body['tools'] = [row for row in body['tools']
                                         if row.get('function', {}).get('name') in allowed]
                    body = runtime_request(body, runtime_info, native_context=native_context)
                    metrics['runtime_allowance'] = runtime_info
                    # Include the allowance/finalization instruction in the
                    # context bound too. A just-under-limit history must not
                    # fail only because the host appended its own feedback.
                    if worker_call and native_context:
                        for recent in (2, 1, 0):
                            if (len(provider_json(body['messages'])) <= MAX_CONTEXT_BYTES
                                    and prompt_bound(provider_json(body))[0] <= MAX_PROMPT_TOKENS):
                                break
                            body, archived = bounded_history(body, self.tasks,
                                max_bytes=min(MAX_CONTEXT_BYTES, len(provider_json(body['messages'])) - 1),
                                recent_turns=recent, compact=True)
                            if archived is not None:
                                metrics.setdefault('history_projections', []).append(archived)
                    metrics.update(messages_bytes=len(provider_json(body['messages'])),
                                   tools_bytes=len(provider_json(body.get('tools'))))
                    if (len(provider_json(body['messages'])) > MAX_CONTEXT_BYTES
                            or prompt_bound(provider_json(body))[0] > MAX_PROMPT_TOKENS):
                        raise BudgetError('context_limit_exhausted')
                    remaining = runtime_info['request_token_allowance']
                request, reserve = completion_request(body, models=self.models, remaining=remaining,
                                                      diagnostics=metrics,
                                                      minimum_output_tokens=(MIN_OUTPUT_TOKENS
                                                          if self.runtime_policy is not None else 1))
                ticket = self.budget.reserve("tokens", reserve)
                if runtime_info is not None:
                    self.runtime_policy.admitted(runtime_info)
                metrics.update(admitted=True, reservation=reserve)
            except BudgetError as exc:
                metrics["rejection"] = ("bounded_prompt_does_not_fit" if exc.args == (
                    "insufficient tokens for bounded prompt and completion",) else "budget_unavailable")
                if self.runtime_policy is not None:
                    if str(exc) in {'context_limit_exhausted', 'phase_call_budget_exhausted'}:
                        metrics['rejection'] = str(exc)
                    self.stop_reason = ("phase_token_budget_exhausted"
                    if metrics["rejection"] == "bounded_prompt_does_not_fit"
                        and remaining < self.budget.available('tokens') else str(exc)
                        if str(exc) in {'context_limit_exhausted', 'phase_call_budget_exhausted'}
                        else "token_admission_exhausted")
                elif metrics["rejection"] == "bounded_prompt_does_not_fit":
                    # No retries/extra planner completions after an admission
                    # failure. The supervisor closes the tree and saves a
                    # terminal blocked summary from existing evidence only.
                    self.stop_reason = "token_admission_exhausted"
                raise
            finally:
                dump(self.private / "provider-requests.json", self.provider_requests)
                if self.runtime_policy is not None:
                    dump(self.private / "runtime-policy.json", self.runtime_policy.snapshot())
            dump(self.private / "budget.json", self.budget.snapshot())
            response, measured, safe_usage = None, None, None
            status, error, encoding = None, None, None
            failure_reason, accounting_shape, response_bytes = None, None, None
            accounting_basis = None
            self.calls += 1
            if self.budget.checkpoint is not None:
                self.budget.checkpoint()
            try:
                import requests
                with requests.Session() as session:
                    session.trust_env = False
                    with session.post(self.provider.rstrip("/") + "/chat/completions", data=provider_json(request),
                            headers={self.api_key_header: ("Bearer " + self.api_key
                                     if self.api_key_header == "Authorization" else self.api_key),
                                     "Content-Type": "application/json"}, allow_redirects=False,
                            timeout=min(360, self.budget.remaining_seconds()), stream=True) as upstream:
                        with self.transport_lock:
                            self.upstream = upstream
                        self._require_open()
                        status = upstream.status_code
                        header = upstream.headers.get("Content-Encoding", "identity").strip().lower()
                        encoding = header if header in {"identity", "gzip", "deflate", "br", "zstd"} else "other"
                        if upstream.status_code != 200:
                            raise BudgetError(f"provider HTTP {status}; response body withheld")
                        # requests' raw stream otherwise returns compressed wire
                        # bytes. Bound the decoded JSON body, including gzip/br.
                        raw = upstream.raw.read(MAX_BODY + 1, decode_content=True)
                        response_bytes = len(raw)
                        if len(raw) > MAX_BODY:
                            raise BudgetError("provider response too large")
                        response = json.loads(raw)
                        accounting_shape = provider_usage_diagnostics(response)
                if not isinstance(response, dict):
                    raise BudgetError('provider response is not an object', code='response_object_invalid')
                if response.get('error') is not None:
                    raise BudgetError('provider returned an error', code='provider_response_error')
                choices = response.get('choices')
                nonempty_completion = isinstance(choices, list) and any(
                    isinstance(row, dict) and isinstance(row.get('message'), dict) and any(
                        row['message'].get(field) for field in (
                            'content', 'tool_calls', 'function_call', 'refusal', 'reasoning', 'reasoning_content'))
                    for row in choices)
                usage, accounting_basis = provider_accounting_usage(
                    response.get('usage'), provider=self.provider, model=request['model'],
                    nonempty_completion=nonempty_completion)
                measured = usage_tokens(usage)
                safe_usage = {key: usage[key] for key in ("prompt_tokens", "completion_tokens", "total_tokens")
                              if key in usage}
                for key, subset in (("prompt_tokens_details", "cached_tokens"),
                                    ("completion_tokens_details", "reasoning_tokens")):
                    if isinstance(usage.get(key), dict):
                        detail = usage[key]
                        safe_usage[key] = ({subset: detail[subset]}
                                           if detail.get(subset) is not None else {})
                if (usage['prompt_tokens'] > metrics['prompt_upper_bound']
                        or usage['completion_tokens'] > metrics['admitted_output_tokens']):
                    measured = None
                    raise BudgetError('provider usage exceeded admitted prompt or output bound')
                if not isinstance(response.get("choices"), list) or not response["choices"]:
                    raise BudgetError("provider response omitted choices")
            except Exception as exc:
                # Never retain exception text: requests exceptions can contain
                # URLs, headers or private response data. Status is sufficient.
                error = type(exc).__name__
                failure_reason = provider_failure_reason(exc, status)
                self.stop_reason = failure_reason
                raise provider_failure(failure_reason, status, reservation_retained=measured is None) from None
            finally:
                with self.transport_lock:
                    self.upstream = None
                try:
                    self.budget.settle(ticket, measured, model=request["model"],
                                       runtime_phase=runtime_info['phase'] if runtime_info else None,
                                       task_spec_id=metrics["task_spec_id"],
                                       usage=safe_usage,
                                       upstream_http_status=status, provider_error=error,
                                       provider_failure_reason=failure_reason,
                                       usage_diagnostics=accounting_shape,
                                       accounting_basis=accounting_basis,
                                       provider_content_encoding=encoding,
                                       prompt_upper_bound=metrics["prompt_upper_bound"],
                                       reserved_output_tokens=metrics["admitted_output_tokens"],
                                       bound_profile=metrics['bound_profile'],
                                       cost_usd=None)
                except BudgetError:
                    if failure_reason is not None:
                        # Settlement retains the reservation, but must not
                        # replace a transport/HTTP diagnosis with missing usage.
                        raise provider_failure(failure_reason, status, reservation_retained=True) from None
                    raise
                finally:
                    dump(self.private / "budget.json", self.budget.snapshot())
                    self.provider_responses.append({
                        'call': self.calls, 'model': request['model'],
                        'upstream_http_status': status, 'content_encoding': encoding,
                        'decoded_response_bytes': response_bytes,
                        'failure_reason': failure_reason, 'usage_diagnostics': accounting_shape,
                        'accounting_basis': accounting_basis, 'accounted_usage': safe_usage})
                    dump(self.private / 'provider-response-diagnostics.json', self.provider_responses)
            if not body.get("stream"):
                return "application/json", json.dumps(response).encode()
            # OpenCode's stream consumer receives the exact buffered completion
            # and final usage; upstream retries/extra sample generation are absent.
            common = {k: response[k] for k in ("id", "created", "model") if k in response}
            choices = []
            for i, row in enumerate(response["choices"]):
                message = dict(row["message"])
                if "tool_calls" in message:
                    message["tool_calls"] = [{**t, "index": j} for j, t in enumerate(message["tool_calls"])]
                choices.append({"index": row.get("index", i), "delta": message, "finish_reason": None})
            chunks = [{**common, "object": "chat.completion.chunk", "choices": choices},
                      {**common, "object": "chat.completion.chunk", "choices": [
                          {"index": row.get("index", i), "delta": {}, "finish_reason": row.get("finish_reason")}
                          for i, row in enumerate(response["choices"])]},
                      {**common, "object": "chat.completion.chunk", "choices": [], "usage": response["usage"]}]
            return "text/event-stream", ("".join("data: " + json.dumps(c) + "\n\n" for c in chunks)
                                          + "data: [DONE]\n\n").encode()

    def dispatch(self, path, body):
        self._require_open()
        if path == "/ready":
            if body != {"nonce": self.nonce}:
                raise ValueError("wrong runtime nonce")
            self.ready = True
            return 200, "application/json", b'{"ready":true}'
        if not self.ready:
            raise ValueError("native runtime not ready")
        if path == "/v1/chat/completions":
            ctype, data = self.completion(body)
            return 200, ctype, data
        if path == "/gate":
            return 200, "application/json", json.dumps(self.gate(body)).encode()
        if path == '/task-complete':
            return 200, 'application/json', json.dumps(self.record_task_completion(body)).encode()
        group = path.removeprefix("/mcp/")
        if not path.startswith("/mcp/") or group not in self.catalog:
            raise ValueError("unknown broker endpoint")
        method, ident, params = body.get("method"), body.get("id"), body.get("params") or {}
        if body.get("jsonrpc") != "2.0":
            raise ValueError("invalid JSON-RPC")
        if method == "notifications/initialized":
            return 202, "application/json", b""
        if method == "initialize":
            version = params.get("protocolVersion", "2024-11-05")
            if version not in {"2024-11-05", "2025-03-26", "2025-06-18"}:
                version = "2025-06-18"
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                      "serverInfo": {"name": group, "version": "native-broker/1"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.catalog[group]}
        elif method == "tools/call":
            try:
                result = self.call_tool(group, params.get("name"), params.get("arguments") or {})
            except (ValueError, RuntimeError) as exc:
                result = {"content": [{"type": "text", "text": str(exc)[:300]}], "isError": True}
        else:
            return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": ident,
                "error": {"code": -32601, "message": "method unavailable"}}).encode()
        return 200, "application/json", json.dumps({"jsonrpc": "2.0", "id": ident, "result": result}).encode()


def make_server(path, broker):
    trace_lock = threading.Lock()

    class Server(ThreadingMixIn, UnixStreamServer):
        daemon_threads = True
        # A full AF_UNIX accept queue returns EAGAIN immediately. Allow the
        # bounded native MCP startup burst without losing whole tool groups.
        request_queue_size = 64

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            started = time.monotonic()
            body, error = None, None
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_BODY:
                    raise ValueError("invalid request size")
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise ValueError("object required")
                status, ctype, raw = broker.dispatch(self.path, body)
            except Exception as exc:
                error = type(exc).__name__
                status, ctype = 400, "application/json"
                # Never leak upstream URLs, credentials, exception tracebacks or state.
                raw = json.dumps({"error": {"message": type(exc).__name__, "type": "benchmark_denied"}}).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                # Native clients may disappear while their group is stopped.
                # Accounting and artifacts were already settled by dispatch.
                pass
            finally:
                # Startup/control metadata only. Do not log RPC arguments or
                # provider bodies, which may contain private target evidence.
                group = self.path.removeprefix("/mcp/")
                if self.path.startswith("/mcp/") and group in CATALOG:
                    method = body.get("method") if isinstance(body, dict) else None
                    if not isinstance(method, str) or method not in {
                            "initialize", "notifications/initialized", "tools/list", "tools/call", "ping"}:
                        method = "unsupported"
                    ident = body.get("id") if isinstance(body, dict) else None
                    event = {"group": group, "method": method, "status": status,
                             "request_id": ident if type(ident) is int else None,
                             "error": error, "response_bytes": len(raw),
                             "seconds": time.monotonic() - started}
                    with trace_lock, (broker.private / "transport-events.jsonl").open("a") as trace:
                        trace.write(json.dumps(event) + "\n")

    return Server(str(path), Handler)
