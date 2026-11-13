"""Direct host execution for python-workflow-v1; no native bridge or file writes.

Reuse the host MCP/policy/wire and provider accounting paths. Only the host
owns keys and raw artifacts; the model receives bounded reference views.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

from full_agent_broker import Broker, dump, runtime_request
from full_agent_budget import BudgetError, completion_request, prompt_bound, provider_json
from full_agent_runtime_policy import (MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS,
                                       MIN_OUTPUT_TOKENS, PHASE_WEIGHTS, RuntimePolicy)
from orchestration_spec import COMPILED_WORKFLOW_TOOL

PHASE_CALL_LIMITS = {"recon": 12, "enum": 16, "access": 14, "report": 6, "planner": 8}
SUMMARY_TOOL = "submit_phase_summary"
READ_TOOL = "read_artifact"
SESSION_CHECK_TOOL = "validator_session_vault_check"
CRAWL_TOOL = "kali-tools_crawl_web_surface"
COVERAGE_TOOL = "hunter_coverage_report"
REPORT_CARRYOVER_STEP = "unresolved-work"


class SessionBindingError(ValueError):
    """A vault lookup must use an exact host-registered target/identity pair."""

    def __init__(self):
        super().__init__("session binding mismatch")


class HandoffError(ValueError):
    """Stable host-operation failure with an optional archived tool result."""

    def __init__(self, code, evidence_ref=None):
        super().__init__(code.replace("_", " "))
        self.code, self.evidence_ref = code, evidence_ref


class ClosureError(ValueError):
    """Stable closure failure without leaking executor or provider text."""

    def __init__(self, code, evidence_ref=None):
        super().__init__(code.replace('_', ' '))
        self.code, self.evidence_ref = code, evidence_ref


class PythonRuntimePolicy(RuntimePolicy):
    """Fixed phase shares, one reserved repair and a consecutive error brake."""

    def __init__(self, budget):
        super().__init__(budget)
        self.limits = {phase: budget.limits["tokens"] * weight // 100
                       for phase, weight in PHASE_WEIGHTS.items()}
        self.limits["planner"] += budget.limits["tokens"] - sum(self.limits.values())
        self.consecutive_failures = {}
        self.repairing = set()
        self.handoff_reserves = {}
        self.validation_reserves = {}
        self.checkpoint_reserves = {}
        self.host_finalizing = set()
        self.summary_prompt_tokens = {}

    def reserve_handoff(self, spec, session_count):
        if spec.phase != "enum" or type(session_count) is not int or session_count < 0:
            raise ValueError("invalid handoff reservation")
        reserve = session_count + 1
        if reserve > min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]):
            raise BudgetError("handoff_tool_budget_exhausted")
        self.handoff_reserves[spec.id] = reserve

    def tool_allowance(self, spec):
        reserved = (0 if spec.id in self.host_finalizing else
                    self.handoff_reserves.get(spec.id, 0) + self.validation_reserves.get(spec.id, 0)
                    + self.checkpoint_reserves.get(spec.id, 0))
        return max(0, min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase])
                   - reserved - self.tool_calls.get(spec.id, 0))

    def prepare(self, spec, prompt_tokens):
        remaining, phase, ident = self.allowance(spec)
        count = self.calls.get(ident, 0)
        limit = PHASE_CALL_LIMITS[phase]
        repair = ident in self.repairing
        if count >= limit or (not repair and count >= limit - 1):
            raise BudgetError("phase_call_budget_exhausted")
        # Cover a fresh repair prompt and, when access still needs a host
        # validator, another summary turn to consume that real tool result.
        # Include usable output and the shared provider allowance metadata.
        pending_validation = bool(self.validation_reserves.get(ident, 0))
        # Closing turns advertise the summary schema, not every probe schema.
        # The projector measures that real shape before provider admission.
        closing_prompt = min(prompt_tokens, self.summary_prompt_tokens.get(ident, prompt_tokens))
        reserve = (closing_prompt + MIN_OUTPUT_TOKENS + 1024) * (1 + pending_validation)
        closing_turns = 2 + pending_validation
        if (not repair and (count >= limit - closing_turns or self.tool_allowance(spec) == 0
                            or remaining < prompt_tokens + MIN_OUTPUT_TOKENS + reserve)):
            self.finalizing.add(ident)
        if ident in self.finalizing:
            # A growing context must not reserve the entire phase for future
            # copies of itself. Finalization advertises summary-only tools;
            # retain half the remaining share for its bounded follow-up/repair.
            # Every actual turn still passes exact prompt/output admission.
            reserve = min(reserve, remaining // 2)
        return {"phase": phase, "spec_id": ident, "phase_token_limit": self.limits[phase],
                "remaining_phase_tokens": remaining, "remaining_phase_calls": limit - count,
                "provider_calls_used": count, "provider_call_limit": limit,
                "request_token_allowance": remaining if repair else max(0, remaining - reserve),
                "remaining_tool_calls": self.tool_allowance(spec),
                "reserved_handoff_tool_calls": self.handoff_reserves.get(ident, 0),
                "finalizing": repair or ident in self.finalizing, "finish_reserve_tokens": reserve,
                "reserved_validation_tool_calls": self.validation_reserves.get(ident, 0),
                "reserved_checkpoint_tool_calls": self.checkpoint_reserves.get(ident, 0)}

    def allowed_tools(self, spec):
        allowed = {SUMMARY_TOOL}
        if (spec.id not in self.repairing
                and (spec.id not in self.finalizing or spec.id in self.host_finalizing)
                and self.consecutive_failures.get(spec.id, 0) < 2
                and self.tool_allowance(spec) > 0):
            allowed |= set(spec.tools) | {READ_TOOL}
        if getattr(spec, "compiled_workflows", None):
            # A compiled task cannot bypass source dependencies by selecting
            # a separately listed raw HTTP or validator entry point.
            allowed &= {SUMMARY_TOOL, READ_TOOL, COMPILED_WORKFLOW_TOOL}
        return allowed

    def check_tool(self, spec, tool):
        if self.consecutive_failures.get(spec.id, 0) >= 2:
            raise BudgetError("consecutive_tool_failure_limit")
        count = self.tool_calls.get(spec.id, 0)
        if count >= min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]):
            raise BudgetError("phase_tool_budget_exhausted")
        if self.tool_allowance(spec) == 0:
            raise ValueError("tool allowance reserved for host handoff")
        if tool not in self.allowed_tools(spec):
            raise ValueError("tool unavailable in current phase or repair")
        self.tool_calls[spec.id] = count + 1

    def record_result(self, spec, tool, execution, error=None):
        super().record_result(spec, tool, execution, error)
        failed = self.tool_failures.get((spec.id, tool), 0) > 0
        self.consecutive_failures[spec.id] = self.consecutive_failures.get(spec.id, 0) + 1 if failed else 0

    def snapshot(self):
        snapshot = super().snapshot()
        for name in ("finalization_turns", "phase_finalization_turns", "finalization_tool_reserve"):
            snapshot.pop(name)
        return {**snapshot, "schema": "python-runtime-policy/1",
                "provider_call_limits": PHASE_CALL_LIMITS, "tool_call_limits": PHASE_CALL_LIMITS,
                "consecutive_tool_failure_limit": 2, "summary_repair_limit": 1,
                "consecutive_failures": dict(self.consecutive_failures),
                "repairing": sorted(self.repairing),
                "handoff_tool_reserves": dict(self.handoff_reserves),
                "validation_tool_reserves": dict(self.validation_reserves),
                "checkpoint_tool_reserves": dict(self.checkpoint_reserves),
                "host_finalizing": sorted(self.host_finalizing)}


class PythonBroker(Broker):
    """Call MCP directly; native dispatch/gate/file-writing are not model APIs."""

    def __init__(self, *, workflow_sender=None, **kwargs):
        super().__init__(**kwargs)
        self.runtime_policy = PythonRuntimePolicy(self.budget)
        self.results = []
        self.references = {}
        self.advertised_tools = None
        self.workflow_sender = workflow_sender
        self.workflow_bindings = {}

    def bind_workflow(self, task_spec_id, manifest, **binding_args):
        """Host API: bind compiled evidence, never accept manifests from the LLM."""
        from python_workflow_binding import WorkflowBinding
        self._require_open()
        spec = next((s for s in self.tasks.specs if s.id == task_spec_id), None)
        if spec is None:
            raise ValueError('unknown workflow TaskSpec')
        binding = WorkflowBinding(spec, manifest, policy_engine=self.engine, **binding_args)
        binding.check(self, spec, registered=False)
        ref = binding.reference
        self.workflow_bindings[ref] = binding
        spec.compiled_workflows[ref] = copy.deepcopy(binding.envelope)
        return ref

    def execute_workflow(self, spec, args):
        from chain_executor import ChainExecutor, _default_sender
        from evidence_chaining import EvidenceError
        from evidence_trust import attest
        from python_workflow_binding import EVIDENCE_PURPOSE
        self.runtime_policy.check_tool(spec, COMPILED_WORKFLOW_TOOL)
        if set(args) != {'binding_ref'} or not isinstance(args.get('binding_ref'), str):
            self.runtime_policy.record_result(spec, COMPILED_WORKFLOW_TOOL, None, 'denied')
            raise ValueError('compiled workflow requires only binding_ref')
        binding = self.workflow_bindings.get(args['binding_ref'])
        if binding is None:
            self.runtime_policy.record_result(spec, COMPILED_WORKFLOW_TOOL, None, 'denied')
            raise ValueError('unknown compiled workflow reference')
        with self.lock:
            self._require_open()
            ticket, result, failure, sent = None, None, None, 0
            artifact = self.private / f'tool-{len(self.tools):04d}.json'
            try:
                binding.check(self, spec)
                ticket = self.budget.reserve('http', binding.manifest['budget']['max_requests'])
                def sender(method, url, headers, body, timeout):
                    nonlocal sent
                    # The gate already checked prerequisites; clamp the actual
                    # transport timeout to the remaining shared wall clock.
                    sent += 1
                    value = (self.workflow_sender or _default_sender)(
                        method, url, headers, body, min(timeout, self.budget.remaining_seconds()))
                    if value.get('status') in {429, 503}:
                        self.stop_reason = 'service_degradation'
                    return value
                runner = ChainExecutor(policy_engine=self.engine, sender=sender,
                    identities=binding.identities, evidence_graph=binding.graph,
                    evidence_context=binding.runtime, write_context=binding.write_context,
                    session_max_retries=0)
                # Keep each tested principal explicit across every step.
                runner.sender = runner.transport.request
                def wire_check(tool, url, method, headers):
                    if self.stop_reason:
                        raise EvidenceError(self.stop_reason)
                    binding.wire_check(self, spec, tool, url, method, headers)
                runner.prerequisite_check = wire_check
                result = runner.execute(copy.deepcopy(binding.manifest))
                if 'business_logic' in binding.manifest:
                    steps = result.get('steps_executed', [])
                    detail = steps[-1].get('oracle_detail', {}) if steps else {}
                    if (len(steps) == len(binding.manifest['steps']) and not result.get('terminal_error')
                            and detail.get('normal_control_passed') is True):
                        result.update(status='completed', verdict='CONFIRMED' if result['success'] else 'NOT_CONFIRMED',
                                      terminal='succeed' if result['success'] else 'fail', effect=detail)
                binding.check(self, spec)
                if self.stop_reason:
                    raise EvidenceError(self.stop_reason)
            except (EvidenceError, ValueError, KeyError, TypeError, OSError) as exc:
                failure = type(exc).__name__
                result = {**(result or {'requests_sent': sent, 'steps_executed': []}),
                          'success': False, 'status': 'blocked', 'verdict': 'INCONCLUSIVE',
                          'execution_failed': True, 'error': 'workflow_prerequisite_denied'}
            finally:
                if ticket is not None:
                    # Count attempts at the sender boundary even when a sender
                    # raises after transmission, rather than charging zero.
                    self.budget.settle(ticket, sent,
                                       tool=COMPILED_WORKFLOW_TOOL, origin='solver', task_spec_id=spec.id)
                self.runtime_policy.record_result(spec, COMPILED_WORKFLOW_TOOL,
                                                  {'result': {'output': result}} if result else None, failure)
                dump(self.private / 'budget.json', self.budget.snapshot())
                dump(artifact, {'tool': COMPILED_WORKFLOW_TOOL, 'arguments': args,
                                'execution': result, 'origin': 'solver', 'error': failure, 'task_spec_id': spec.id})
                self.tools.append({'tool': COMPILED_WORKFLOW_TOOL, 'artifact': str(artifact),
                                   'origin': 'solver', 'task_spec_id': spec.id})
            payload = {'schema': 'python-compiled-workflow-execution/1', 'task_spec_id': spec.id,
                       'binding_ref': args['binding_ref'], 'binding': binding.envelope['payload'],
                       'result': result, 'reportable': False}
            return {'status': result.get('status', 'completed'), 'success': result.get('success', False),
                    'execution_failed': result.get('execution_failed', False),
                    'requests_sent': result['requests_sent'], 'reportable': False,
                    'signed_evidence': attest(payload, EVIDENCE_PURPOSE)}

    def verified_workflow_executions(self, spec):
        """Signed execution coverage stays distinct from a reportable finding."""
        from evidence_trust import canonical_bytes, verify
        from python_workflow_binding import EVIDENCE_PURPOSE
        coverage = {ref: {'binding_ref': ref, 'status': 'NOT TESTED'} for ref in spec.compiled_workflows}
        for row in self.results:
            if row['spec_id'] != spec.id or row['tool'] != COMPILED_WORKFLOW_TOOL:
                continue
            ref = row['content_ref']
            raw = (self.workdir / ref['path']).read_bytes()
            if hashlib.sha256(raw).hexdigest() != ref['sha256']:
                raise ValueError('workflow evidence changed')
            value = json.loads(raw)
            signed = value.get('signed_evidence', {})
            payload = signed.get('payload', {})
            ident = payload.get('binding_ref')
            if (ident not in coverage or payload.get('task_spec_id') != spec.id
                    or not verify(canonical_bytes(payload), signed, EVIDENCE_PURPOSE)):
                continue
            try:
                self.workflow_bindings[ident].check(self, spec)
            except (ValueError, KeyError, TypeError, OSError):
                continue
            result = payload.get('result', {})
            if result.get('terminal') in {'succeed', 'fail', 'abort'} and not result.get('execution_failed'):
                coverage[ident] = {'binding_ref': ident, 'status': 'TESTED' if result.get('terminal') in {'succeed', 'fail'} else 'NOT TESTED',
                                  'verdict': result.get('verdict', 'CONFIRMED' if result.get('success') else 'INCONCLUSIVE'),
                                  'evidence_ref': ref, 'reportable': False}
        return list(coverage.values())

    def completion(self, body):
        self.advertised_tools = None
        content_type, raw = super().completion(body, native_context=False)
        if content_type != "application/json":
            raise ValueError("Python solver requires buffered JSON")
        return json.loads(raw)

    def project_runtime_context(self, body, spec, info):
        """Fit a host context before one provider dispatch, retaining its archive.

        Try the full context, older read references, then the latest result.
        Only a summary-only closing request may omit that latest page's text.
        Admission uses the same allowance message, tokenizer and output floor
        as the actual request; projections never consume provider/tool calls.
        """
        messages = body.get('messages', [])
        try:
            context = json.loads(messages[1]['content'])
        except (IndexError, KeyError, TypeError, ValueError):
            return body, self.runtime_policy.prepare(spec, prompt_bound(provider_json(body))[0]), None
        if not isinstance(context, dict) or context.get('schema') != 'python-workflow-v1':
            return body, self.runtime_policy.prepare(spec, prompt_bound(provider_json(body))[0]), None
        source_ref = None
        initial_finalizing = set(self.runtime_policy.finalizing)
        for level in range(4):
            self.runtime_policy.finalizing = set(initial_finalizing)
            candidate = copy.deepcopy(body)
            projected = copy.deepcopy(context)
            if level:
                source_ref = source_ref or self.archive(context, 'provider-context')
                projected['context_archive_ref'] = source_ref
                recent = projected.get('recent_results', [])
                for row in recent[:-1]:
                    if row.get('tool') == READ_TOOL and 'text' in row.get('result', {}):
                        row['result'].pop('text')
                        row['result']['text_archived'] = True
                if level >= 2:
                    projected['older_results'] = ([*projected.get('older_results', []), *[
                        {'tool': row['tool'], 'content_ref': row['content_ref']}
                        for row in recent[:-1]]])[-8:]
                    projected['recent_results'] = recent[-1:]
                    # These are host-owned contracts and archived prior
                    # outputs. The model needs goals, authority references and
                    # exact evidence pointers, not duplicate tool inventories.
                    projected['task_spec'] = {key: value for key, value in projected['task_spec'].items()
                                              if key in {'id', 'phase', 'target', 'steps', 'vector', 'references'}}
                    projected['task_spec']['steps'] = [
                        {key: value for key, value in step.items() if key != 'goal'}
                        for step in projected['task_spec']['steps']]
                    # The exact current allowance is appended by the host in
                    # the final wire request. Do not send a duplicate copy.
                    for key in list(projected):
                        if key.startswith(('remaining_', 'reserved_')):
                            projected.pop(key)
                    projected.pop('handoff', None)
                    projected['handoff_host_managed'] = True
                    for key in ('previous_summary', 'handoff', 'discovery'):
                        value = projected.get(key)
                        if isinstance(value, dict) and value.get('content_ref'):
                            projected[key] = {'content_ref': value['content_ref'], 'result_archived': True}
                    if spec.phase == 'access' and projected.get('discovery'):
                        # Discovery and the complete source context already
                        # retain the enum evidence. Avoid a third copy of its
                        # archive reference in the first validation turn.
                        projected.pop('previous_summary', None)
                    if (recent and recent[-1].get('tool') == READ_TOOL
                            and 'text' in recent[-1].get('result', {})):
                        # Keep the fresh evidence page readable. A compact
                        # workflow tool set leaves room for that page while
                        # retaining discovery, session checks and validation.
                        reading_tools = {READ_TOOL, SUMMARY_TOOL, SESSION_CHECK_TOOL,
                                         COVERAGE_TOOL, 'hunter_run_web_loop'}
                        candidate['tools'] = [row for row in candidate['tools']
                                              if row['function']['name'] in reading_tools]
                if level == 3:
                    self.runtime_policy.finalizing.add(spec.id)
                    for row in projected['recent_results']:
                        protected = {'ok', 'status', 'status_code', 'error', 'verdict', 'confirmed',
                                     'validation_id', 'offset', 'next_offset', 'eof', 'content_ref'}
                        result = row.get('result')
                        result = result if isinstance(result, dict) else {}
                        row['result'] = {key: value for key, value in result.items()
                                         if key in protected and len(provider_json(value)) <= 512}
                        row['result_archived'] = True
                    # The host owns validation, handoff and the immutable spec.
                    # A closing model needs step IDs, current outcomes and
                    # repair feedback; the complete context remains archived.
                    task = projected['task_spec']
                    task = {key: task[key] for key in ('id', 'phase', 'target', 'steps')}
                    task['steps'] = [{key: value for key, value in step.items()
                                     if key != 'goal'} for step in task['steps']]
                    projected = {key: projected[key] for key in
                                 ('schema', 'context_archive_ref', 'recent_results', 'summary_feedback')}
                    projected['task_spec'] = task
            candidate['messages'][1]['content'] = provider_json(projected).decode()
            closing = {**candidate, 'tools': [row for row in candidate.get('tools', [])
                                             if row['function']['name'] == SUMMARY_TOOL]}
            self.runtime_policy.summary_prompt_tokens[spec.id] = prompt_bound(provider_json(closing))[0]
            info = self.runtime_policy.prepare(spec, prompt_bound(provider_json(candidate))[0])
            if info['finalizing'] and spec.id not in initial_finalizing and level < 2:
                # Try less history before committing a budget transition.
                # No model or tool calls have been made for these previews.
                continue
            allowed = self.runtime_policy.allowed_tools(spec)
            candidate['tools'] = [row for row in candidate['tools']
                                  if row['function']['name'] in allowed]
            info = self.runtime_policy.prepare(spec, prompt_bound(provider_json(candidate))[0])
            wire = runtime_request(candidate, info, native_context=False)
            try:
                if (len(provider_json(wire['messages'])) > MAX_CONTEXT_BYTES
                        or prompt_bound(provider_json(wire))[0] > MAX_PROMPT_TOKENS):
                    raise BudgetError('context_limit_exhausted')
                completion_request(wire, models=self.models, remaining=info['request_token_allowance'],
                                   minimum_output_tokens=MIN_OUTPUT_TOKENS)
            except BudgetError:
                if level == 3:
                    raise
                continue
            projection = ({'schema': 'python-context-projection/1', 'level': level,
                           'source_ref': source_ref, 'latest_result_text_retained': level < 3}
                          if level else None)
            self.advertised_tools = {row['function']['name']: copy.deepcopy(row['function']['parameters'])
                                     for row in candidate.get('tools', [])}
            return candidate, info, projection
        raise AssertionError('unreachable projection state')

    def archive(self, value, label="tool-result"):
        raw = provider_json(value)
        digest = hashlib.sha256(raw).hexdigest()
        relative = f"context-archive/{label}-{digest}.json"
        path = self.workdir / relative
        path.parent.mkdir(exist_ok=True)
        if path.exists() and (path.is_symlink() or path.read_bytes() != raw):
            raise ValueError("context archive changed")
        if not path.exists():
            with path.open("xb") as handle:
                handle.write(raw)
        ref = {"path": relative, "sha256": digest, "bytes": len(raw)}
        self.references[relative] = ref
        return ref

    def view(self, value, label="tool-result"):
        ref = self.archive(value, label)
        if len(provider_json(value)) <= 3000:
            return {"result": value, "content_ref": ref}
        # Bounded shape/decisions; exact bytes always remain in content_ref.
        protected = {"ok", "confirmed", "verdict", "error", "execution_failed", "stop_reason",
                     "status", "status_code", "url", "target", "validation_id"}
        if isinstance(value, dict) and 'signed_evidence' in value:
            protected |= {'requests_sent', 'success', 'reportable'}
        result = {key: item for key, item in value.items()
                  if key in protected and len(provider_json(item)) <= 512} if isinstance(value, dict) else {}
        return {"result": result, "content_ref": ref, "omitted": True,
                "fields": list(value)[:32] if isinstance(value, dict) else [],
                "items": len(value) if isinstance(value, (list, dict)) else None}

    def session_checks(self, spec):
        # Project only safe lookup arguments. A registration is not evidence
        # of current freshness, and never widens the immutable TaskSpec target.
        return [{"target": spec.target, "identity": identity}
                for identity, binding in sorted(self.tasks.bindings.items())
                if isinstance(identity, str) and identity and isinstance(binding, dict)
                and binding.get("target") == spec.target]

    def invoke(self, tool, args):
        self._require_open()
        spec = self.tasks.active_spec
        if spec is None:
            raise ValueError("no active TaskSpec")
        if not isinstance(args, dict):
            raise ValueError("tool arguments must be an object")
        args = dict(args)
        if spec.references and tool != READ_TOOL:
            # brain.observed_specs is an observation planner. Its selection
            # never authorizes live work or a broader validation slice.
            if (tool != 'hunter_run_web_loop' or args.get('live', False) is not False
                    or args.get('target', spec.target) != spec.target):
                raise ValueError('observed TaskSpec permits exact-target planning only')
            args.update(target=spec.target, live=False)
        if tool == CRAWL_TOOL and self.session_checks(spec):
            checks = self.session_checks(spec)
            # Prefer a member's observed surface; admin credentials are not
            # an implicit authorization oracle. No credentials cross the API.
            members = [row for row in checks if self.tasks.bindings[row["identity"]].get("role") == "member"]
            identity = args.get("identity", (members or checks)[0]["identity"])
            target = args.get("session_target", spec.target)
            observed, registered = urlsplit(args.get("target", "")), urlsplit(spec.target)
            if ({"target": target, "identity": identity} not in checks
                    or (observed.scheme, observed.netloc) != (registered.scheme, registered.netloc)
                    or observed.username is not None or args.get("cookie") or args.get("headers")):
                self.runtime_policy.check_tool(spec, tool)
                self.runtime_policy.record_result(spec, tool, None, "denied")
                raise SessionBindingError()
            args.update(session_target=target, identity=identity)
        if tool == COVERAGE_TOOL:
            # Missing target is safely bound to the immutable phase target;
            # an explicitly different target is never rewritten.
            if args.get("target", spec.target) != spec.target:
                self.runtime_policy.check_tool(spec, tool)
                self.runtime_policy.record_result(spec, tool, None, "denied")
                raise ValueError("coverage target mismatch")
            args.setdefault("target", spec.target)
        if tool == COMPILED_WORKFLOW_TOOL:
            value = self.execute_workflow(spec, args)
        elif tool == READ_TOOL:
            self.runtime_policy.check_tool(spec, tool)
            ticket = self.budget.reserve("http", 0)
            try:
                ref = self.references.get(args.get("path"))
                if ref is None:
                    raise ValueError("unknown artifact reference")
                path = self.workdir / ref["path"]
                if any(p.is_symlink() for p in (path, *path.parents)):
                    raise ValueError("artifact reference is a symlink")
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
                    raw = handle.read(16 * 1024 * 1024 + 1)
                if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                    raise ValueError("artifact reference changed")
                offset, size = args.get("offset", 0), args.get("limit", 3000)
                if type(offset) is not int or offset < 0 or type(size) is not int or not 1 <= size <= 3000:
                    raise ValueError("invalid bounded artifact range")
                decoded = raw.decode()
                chunk = decoded[offset:offset + size]
                end = min(len(decoded), offset + len(chunk))
                value = {"content_ref": ref, "offset": offset, "text": chunk,
                         "next_offset": end if end < len(decoded) else None,
                         "eof": end >= len(decoded)}
            except (ValueError, OSError):
                self.runtime_policy.record_result(spec, tool, None, "invalid_reference")
                raise ValueError("invalid artifact reference or range") from None
            else:
                self.runtime_policy.record_result(spec, tool, {"result": {"output": value}})
            finally:
                self.budget.settle(ticket, 0, tool=tool, origin="solver")
                dump(self.private / "budget.json", self.budget.snapshot())
        else:
            # Split against the fixed catalog, never accept a model server/module.
            group, sep, name = tool.partition("_")
            if not sep:
                raise ValueError("invalid MCP tool name")
            before = len(self.tools)
            try:
                if tool == SESSION_CHECK_TOOL and {"target": args.get("target"),
                        "identity": args.get("identity", "anon")} not in self.session_checks(spec):
                    # Do not silently rewrite an endpoint into a session target.
                    # Reject before policy/egress and charge the attempted call
                    # to the same allowance and consecutive-failure brake.
                    self.runtime_policy.check_tool(spec, tool)
                    raise SessionBindingError()
                emitted = self.call_tool(group, name, args)
            except ValueError:
                # Policy denials before execution still participate in the brake.
                if len(self.tools) == before:
                    self.runtime_policy.record_result(spec, tool, None, "denied")
                raise
            text = emitted["content"][0]["text"]
            try:
                value = json.loads(text)
            except ValueError:
                value = {"text": text}
            if emitted.get("isError"):
                value = {"execution_failed": True, "output": value}
        # This text is already range-bounded. Passing its metadata wrapper
        # through the generic 3000-byte projection would hide a full page,
        # making the model request the same unreadable artifact indefinitely.
        view = ({"result": value, "content_ref": self.archive(value)}
                if tool == READ_TOOL else self.view(value))
        row = {"spec_id": spec.id, "tool": tool, "arguments": args, **view}
        self.results.append(row)
        dump(self.private / "python-tool-results.json", self.results)
        if spec.phase == "access" and tool == "hunter_run_web_loop":
            reports = [json.loads((self.workdir / item["content_ref"]["path"]).read_bytes())
                       for item in self.results if item["spec_id"] == spec.id
                       and item["tool"] == tool and item["arguments"].get("live") is True]
            reports = [item for item in reports if isinstance(item, dict) and item.get("run_id")]
            (self.workdir / "access").mkdir(exist_ok=True)
            dump(self.workdir / "access/live-result.json", {
                "producer": "host", "run_ids": [item["run_id"] for item in reports],
                "validations": [item for report in reports for item in report.get("validations", [])],
                "confirmed": [item for report in reports for item in report.get("confirmed", [])]})
        if spec.phase == "access":
            self.persist_validation_attempts(spec)
        self.write_attempt_ledger()
        status = value.get("status", value.get("status_code")) if isinstance(value, dict) else None
        if type(status) is int and status in {429, 503}:
            self.stop_reason = "service_degradation"
            raise BudgetError(self.stop_reason)
        return view

    def validation_attempts(self, spec):
        """IDs come only from executed validation tools and current signatures."""
        from brain import _VALIDATOR_VECTOR_TYPES, _VALIDATOR_VECTOR_ALIASES, runtime_root
        validator_path = str(runtime_root() / "mcp-servers/mcp-validator")
        if validator_path not in sys.path:
            sys.path.append(validator_path)
        from cco_validator_core import artifact_is_current, load_validation, normalize_finding_type
        attempts = {}
        for row in self.results:
            if row["spec_id"] != spec.id or not (row["tool"] == "hunter_run_web_loop"
                    or row["tool"].startswith("validator_validate_")):
                continue
            ref = row["content_ref"]
            raw = (self.workdir / ref["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                raise ValueError("validation tool evidence changed")
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("execution_failed") or value.get("error"):
                continue
            candidates = [value, *(value.get("validations") or [])]
            for candidate in candidates:
                if not isinstance(candidate, dict) or not candidate.get("validation_id"):
                    continue
                record = load_validation(candidate["validation_id"])
                if (not record or record.get("verdict") not in {"CONFIRMED", "UNCONFIRMED"}
                        or not record.get("guard", {}).get("transport_ok")):
                    continue
                kind = normalize_finding_type(record.get("vuln_type", ""))
                vector = next((key for key, types in _VALIDATOR_VECTOR_TYPES.items()
                    if kind in {normalize_finding_type(item) for item in
                                (types, *_VALIDATOR_VECTOR_ALIASES.get(key, ()))}), None)
                if not vector or not artifact_is_current(record, expected_target=spec.target, expected_finding_type=kind):
                    continue
                attempts[record["validation_id"]] = {"vector": vector, "record": record,
                    "source_artifact": ref["path"], "source_sha256": ref["sha256"]}
        return list(attempts.values())

    def persist_validation_attempts(self, spec):
        import attempt_ledger as attempts
        folder = self.workdir / "validator-artifacts"
        existing = attempts.read_records(attempts.ledger_path(self.workdir))
        for item in self.validation_attempts(spec):
            record = item["record"]
            folder.mkdir(exist_ok=True)
            artifact = folder / (record["validation_id"] + ".json")
            if artifact.exists() and json.loads(artifact.read_bytes()) != record:
                raise ValueError("validator copy changed")
            if not artifact.exists():
                dump(artifact, record)
            self.archive(record, "validator")
            if any(row.get("note") == record["validation_id"] for row in existing):
                continue
            attempt = {"vector": item["vector"], "endpoint": record["target"],
                "identity": record.get("execution_context", {}).get("identity") or "anon",
                "verdict": record["verdict"], "artifact": artifact.relative_to(self.workdir).as_posix(),
                "note": record["validation_id"]}
            attempts.append_record(attempts.ledger_path(self.workdir), attempt)

    def session_check_evidence(self):
        checks = {}
        for row in self.results:
            if row["spec_id"] == "enum-2" and row["tool"] == SESSION_CHECK_TOOL:
                value = json.loads((self.workdir / row["content_ref"]["path"]).read_bytes())
                if value.get("status") == "fresh":
                    checks[row["arguments"]["identity"]] = value
        return checks

    def write_attempt_ledger(self):
        import attempt_ledger as attempts
        from evidence_trust import attest
        path = attempts.ledger_path(self.workdir)
        records = attempts.read_records(path)
        trusted, errors = attempts.verify_records(records, path=path)
        if errors:
            raise ValueError("attempt ledger integrity error")
        refs = sorted(self.references.values(), key=lambda row: row["path"])
        files = [self.tasks.summary_path(spec) for spec in self.tasks.specs]
        files.extend(self.workdir / name for name in ("handoff.json", "handoff-access.json", "object-pool.json"))
        files.extend(self.workdir / name for name in ("specs.json", "enum/session-checks.json", "access/live-result.json"))
        files.extend(sorted((self.workdir / "validator-artifacts").glob("*.json")))
        snapshots = [{"path": path.relative_to(self.workdir).as_posix(),
                      "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
                     for path in files if path.is_file() and not path.is_symlink()]
        payload = {"schema": "python-attempt-ledger/1", "producer": "host",
                   "target": self.tasks.specs[0].target, "records": trusted,
                   "artifacts": refs, "workflow_files": snapshots}
        dump(self.workdir / "attempt-ledger.json", attest(payload, "python-attempt-ledger"))

    def handoff(self):
        spec = self.tasks.active_spec
        checks = self.session_checks(spec)
        if len(checks) != len(self.tasks.bindings):
            raise HandoffError("handoff_session_binding_invalid")
        self.runtime_policy.reserve_handoff(spec, len(checks))
        remaining = min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]) - self.runtime_policy.tool_calls.get(spec.id, 0)
        if remaining < len(checks) + 1:
            raise BudgetError("handoff_tool_budget_exhausted")
        self.runtime_policy.host_finalizing.add(spec.id)
        try:
            # Provider turns may exceed the 300-second freshness window. Do
            # real policy-gated, charged checks immediately before handoff;
            # never extend the window or assume setup remains fresh.
            for args in checks:
                try:
                    view = self.invoke(SESSION_CHECK_TOOL, args)
                except BudgetError:
                    raise
                except ValueError:
                    raise HandoffError("handoff_session_check_denied") from None
                value = view["result"]
                if (not isinstance(value, dict) or value.get("status") != "fresh"
                        or value.get("error") or value.get("execution_failed")):
                    raise HandoffError("handoff_session_refresh_failed", view["content_ref"])
            if checks:
                (self.workdir / "enum").mkdir(exist_ok=True)
                dump(self.workdir / "enum/session-checks.json", self.session_check_evidence())
            try:
                view = self.invoke("kali-tools_ledger_prepare_handoff", {
                    "target": spec.target, "workdir": str(self.workdir), "vector": "access",
                    "summary_file": f"summaries/{spec.id}.json", "own_ids_json": "[]",
                    "budget_calls": PHASE_CALL_LIMITS["access"],
                    "session_bindings_json": provider_json(self.tasks.bindings).decode()})
            except BudgetError:
                raise
            except ValueError:
                raise HandoffError("handoff_preparation_denied") from None
            if not isinstance(view["result"], dict) or view["result"].get("ok") is not True or "access" not in self.handoffs:
                raise HandoffError("handoff_preparation_failed", view["content_ref"])
            packet = json.loads((self.workdir / "handoff-access.json").read_text())
            dump(self.workdir / "handoff.json", packet)
            self.archive(packet, "handoff")
        finally:
            self.runtime_policy.host_finalizing.discard(spec.id)
            dump(self.private / "runtime-policy.json", self.runtime_policy.snapshot())

    def verified_findings(self, spec):
        """Accept IDs only from actual tools, then use the existing signature gate."""
        from brain import _confirmation_record
        import hypothesis_ledger as hypotheses
        findings = {}
        for row in self.results:
            if row["spec_id"] != spec.id:
                continue
            value = json.loads((self.workdir / row["content_ref"]["path"]).read_bytes())
            if not isinstance(value, dict):
                continue
            candidates = [value, *value.get("validations", [])] if isinstance(value.get("validations", []), list) else [value]
            for candidate in candidates:
                if not isinstance(candidate, dict) or not candidate.get("validation_id"):
                    continue
                for vector in hypotheses.DEFAULT_VECTORS:
                    record, _ = _confirmation_record({"validation_id": candidate["validation_id"]}, vector,
                                                     {"target": spec.target})
                    if record is not None:
                        findings[record["validation_id"]] = {"validation_id": record["validation_id"],
                            "validation_sha256": record["artifact"]["content_sha256"],
                            "vector": vector, "verdict": "CONFIRMED"}
                        break
        return list(findings.values())

    def seal(self):
        """Preserve remaining work as NOT TESTED before the existing closure gate."""
        spec = self.tasks.active_spec
        if spec is None or spec.phase != 'report' or 'kali-tools_ledger_checkpoint' not in spec.tools:
            raise ClosureError('closure_phase_invalid')
        remaining = min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]) - self.runtime_policy.tool_calls.get(spec.id, 0)
        if remaining < 1:
            raise BudgetError('closure_tool_budget_exhausted')
        import hypothesis_ledger as hypotheses
        from brain import _confirmation_record, _confirmation_reference
        import attempt_ledger as attempts
        ledger = hypotheses.load_ledger(self.workdir)
        summary = self.tasks.read_summary(next(s for s in self.tasks.specs if s.phase == "access"))
        reasons = {row["vector"]: row for row in summary.get("not_tested_reasons", [])}
        for finding in summary["findings"]:
            vector = finding["vector"]
            record, _ = _confirmation_record(finding, vector, ledger)
            if record is None:
                raise ValueError("validator receipt became stale")
            hypotheses.mark(ledger, vector, "confirmed", note="host verified validator receipt")
            entry = next(e for e in ledger["hypotheses"] if e["vector"] == vector)
            entry.update(_confirmation_reference(record))
            folder = self.workdir / "validator-artifacts"
            folder.mkdir(exist_ok=True)
            artifact = folder / (record["validation_id"] + ".json")
            dump(artifact, record)
            self.archive(record, "validator")
            existing = attempts.read_records(attempts.ledger_path(self.workdir))
            if not any(row.get("note") == record["validation_id"] for row in existing):
                status = record.get("evidence", {}).get("status")
                attempt = {"vector": vector, "endpoint": record["target"], "identity": "anon",
                           "verdict": "CONFIRMED", "artifact": artifact.relative_to(self.workdir).as_posix(),
                           "note": record["validation_id"]}
                if type(status) is int:
                    attempt["status"] = status
                attempts.append_record(attempts.ledger_path(self.workdir), attempt)
        for entry in ledger["hypotheses"]:
            if entry["status"] not in hypotheses.TERMINAL:
                checks = self.session_check_evidence()
                recovered = bool(checks) and set(checks) == set(self.tasks.bindings)
                reason = reasons.get(entry["vector"], {"reason_code": "outside_completed_validation_slice"})
                if recovered:
                    attempts.append_record(attempts.ledger_path(self.workdir), {
                        "vector": entry["vector"], "endpoint": ledger["target"],
                        "identity": sorted(checks)[0], "verdict": "session-recovery",
                        "artifact": "enum/session-checks.json",
                        "note": "Host-recorded fresh enum session checks; broader probes remain NOT TESTED"})
                hypotheses.mark(ledger, entry["vector"], "not_applicable",
                    note="not_tested:auth:" + ("recovered: " if recovered else "not-required: no session claim for parked work; ")
                    + reason["reason_code"] + "; broader security coverage remains NOT TESTED")
        hypotheses.save_ledger(self.workdir, ledger)
        self.runtime_policy.host_finalizing.add(spec.id)
        try:
            try:
                view = self.invoke('kali-tools_ledger_checkpoint', {'workdir': str(self.workdir), 'seal': True})
            except ValueError:
                raise ClosureError('closure_checkpoint_denied') from None
            result = view['result']
            if (not isinstance(result, dict) or result.get('sealed') is not True
                    or type(result.get('check_exit')) is not int or result['check_exit'] != 0
                    or result.get('execution_failed')):
                raise ClosureError('closure_checkpoint_failed', view['content_ref'])
            return view
        finally:
            self.runtime_policy.host_finalizing.discard(spec.id)
            self.runtime_policy.checkpoint_reserves.pop(spec.id, None)
            dump(self.private / 'runtime-policy.json', self.runtime_policy.snapshot())
