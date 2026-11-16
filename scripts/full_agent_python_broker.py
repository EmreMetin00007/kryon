"""Direct host execution for python-workflow-v1; no native bridge or file writes.

Reuse the host MCP/policy/wire and provider accounting paths. Only the host
owns keys and raw artifacts; the model receives bounded reference views.
"""
from __future__ import annotations

import copy
import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import threading
import time
import uuid
import weakref
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from full_agent_budget import (BudgetError, compact_tools, completion_request,
                               prompt_bound, provider_json)
from full_agent_executor import HostBroker
from full_agent_provider import (PYTHON_ALLOWANCE_INSTRUCTION,
                                 TOOL_DESCRIPTION_LIMIT, dump,
                                 runtime_allowance_request)
from full_agent_runtime_policy import (MAX_CONTEXT_BYTES, MAX_PROMPT_TOKENS,
                                       MIN_OUTPUT_TOKENS, PHASE_WEIGHTS, RuntimePolicy)
from orchestration_spec import COMPILED_WORKFLOW_TOOL
from python_candidate_runtime import (PROFILES, authorization_controls_complete, compact_gaps,
                                      page_cards, query_parameters, upstream_ids)
from python_discovery_runtime import SUMMARY_FRONTIER_BYTES, SUMMARY_FRONTIER_LIMIT, compact_frontier

PHASE_CALL_LIMITS = {"recon": 12, "enum": 16, "access": 14, "report": 6, "planner": 8}
SUMMARY_TOOL = "submit_phase_summary"
READ_TOOL = "read_artifact"
SESSION_CHECK_TOOL = "validator_session_vault_check"
CRAWL_TOOL = "kali-tools_crawl_web_surface"
COVERAGE_TOOL = "hunter_coverage_report"
REPORT_CARRYOVER_STEP = "unresolved-work"
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024


class ArchiveSizeError(ValueError):
    code = "archive_size_limit_exceeded"


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
        self.host_continuing = set()
        self.summary_prompt_tokens = {}
        self._lock = threading.RLock()
        self._pending_executions: dict[str, dict[str, Any]] = {}
        self._conservative_token_charges: dict[str, int] = {}
        self._active_ticket = threading.local()

    def allowance(self, spec):
        remaining, phase, ident = super().allowance(spec)
        with self._lock:
            reserved_tokens = sum(
                item["tokens"] for item in self._pending_executions.values() if item["phase"] == phase
            )
            conservative = self._conservative_token_charges.get(phase, 0)
        return max(0, remaining - reserved_tokens - conservative), phase, ident

    def reserve_handoff(self, spec, session_count):
        if spec.phase != "enum" or type(session_count) is not int or session_count < 0:
            raise ValueError("invalid handoff reservation")
        reserve = session_count + 1
        if reserve > min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]):
            raise BudgetError("handoff_tool_budget_exhausted")
        self.handoff_reserves[spec.id] = reserve

    def tool_allowance(self, spec):
        with self._lock:
            pending_calls = sum(
                max(0, item["calls"] - item["counted_calls"])
                for item in self._pending_executions.values()
                if item["spec_id"] == spec.id
            )
            reserved = (0 if spec.id in self.host_finalizing else
                        self.handoff_reserves.get(spec.id, 0) + self.validation_reserves.get(spec.id, 0)
                        + self.checkpoint_reserves.get(spec.id, 0))
            return max(0, min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase])
                       - reserved - self.tool_calls.get(spec.id, 0) - pending_calls)

    def reserve_execution(self, spec, *, calls: int = 1, estimated_tokens: int = 0, uncertain: bool = False) -> str:
        """Atomically reserve phase call and token budget before dispatching a candidate."""
        if type(calls) is not int or calls < 1:
            raise ValueError("calls reservation must be a positive integer")
        if type(estimated_tokens) is not int or estimated_tokens < 0:
            raise ValueError("estimated_tokens reservation must be a non-negative integer")
        reserve_tokens = max(MIN_OUTPUT_TOKENS, estimated_tokens) if uncertain and estimated_tokens == 0 else estimated_tokens
        with self._lock:
            if self.consecutive_failures.get(spec.id, 0) >= 2:
                raise BudgetError("consecutive_tool_failure_limit")
            if self.tool_allowance(spec) < calls:
                raise BudgetError("phase_tool_budget_exhausted")
            remaining_tokens, phase, _ = self.allowance(spec)
            if reserve_tokens > remaining_tokens:
                raise BudgetError("token_budget_exhausted")
            ticket = uuid.uuid4().hex
            self._pending_executions[ticket] = {
                "spec_id": spec.id,
                "phase": phase,
                "calls": calls,
                "tokens": reserve_tokens,
                "uncertain": bool(uncertain),
                "counted_calls": 0,
            }
            return ticket

    def activate_execution_ticket(self, ticket: str | None):
        class _Guard:
            def __enter__(_self):
                _self.prev = getattr(self._active_ticket, "value", None)
                self._active_ticket.value = ticket
            def __exit__(_self, *_exc):
                self._active_ticket.value = _self.prev
        return _Guard()

    def reconcile_execution(
        self,
        ticket: str,
        *,
        actual_calls: int | None = None,
        actual_tokens: int | None = None,
        measurement_valid: bool = True,
    ) -> None:
        """Atomically reconcile an execution reservation, retaining conservative charges when uncertain."""
        with self._lock:
            item = self._pending_executions.pop(ticket, None)
            if item is None:
                return
            spec_id = item["spec_id"]
            phase = item["phase"]
            if actual_calls is not None and type(actual_calls) is int and actual_calls >= 0:
                extra_calls = actual_calls - item["counted_calls"]
                if extra_calls > 0:
                    self.tool_calls[spec_id] = self.tool_calls.get(spec_id, 0) + extra_calls
            if measurement_valid and type(actual_tokens) is int and 0 <= actual_tokens <= item["tokens"]:
                if actual_tokens > 0:
                    self._conservative_token_charges[phase] = self._conservative_token_charges.get(phase, 0) + actual_tokens
            else:
                # Uncertain or overrun usage conservatively retains the full reservation.
                self._conservative_token_charges[phase] = self._conservative_token_charges.get(phase, 0) + item["tokens"]

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
                and (spec.id not in self.finalizing or spec.id in self.host_finalizing
                     or spec.id in self.host_continuing)
                and self.consecutive_failures.get(spec.id, 0) < 2
                and self.tool_allowance(spec) > 0):
            allowed |= set(spec.tools) | {READ_TOOL}
        if getattr(spec, "compiled_workflows", None):
            # A compiled task cannot bypass source dependencies by selecting
            # a separately listed raw HTTP or validator entry point.
            allowed &= {SUMMARY_TOOL, READ_TOOL, COMPILED_WORKFLOW_TOOL}
        return allowed

    def check_tool(self, spec, tool):
        with self._lock:
            if self.consecutive_failures.get(spec.id, 0) >= 2:
                raise BudgetError("consecutive_tool_failure_limit")
            count = self.tool_calls.get(spec.id, 0)
            if count >= min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]):
                raise BudgetError("phase_tool_budget_exhausted")
            active_ticket = getattr(self._active_ticket, "value", None)
            active_item = self._pending_executions.get(active_ticket) if active_ticket else None
            if active_item is not None and active_item["spec_id"] == spec.id and active_item["counted_calls"] < active_item["calls"]:
                active_item["counted_calls"] += 1
            elif self.tool_allowance(spec) == 0:
                raise ValueError("tool allowance reserved for host handoff")
            if tool not in self.allowed_tools(spec):
                if active_item is not None and active_item["spec_id"] == spec.id and active_item["counted_calls"] > 0:
                    active_item["counted_calls"] -= 1
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
                "host_finalizing": sorted(self.host_finalizing),
                "host_continuing": sorted(self.host_continuing)}


def _close_fd_box(box: list[int | None]) -> None:
    fd = box[0] if box else None
    if fd is not None:
        box[0] = None
        try:
            os.close(fd)
        except OSError:
            pass


def _open_anchored_dir(
    path: Path,
    *,
    expected_identities: tuple[tuple[int, int], ...] | None = None,
) -> tuple[int, tuple[tuple[int, int], ...]]:
    """Open an absolute directory lexically component-by-component with O_NOFOLLOW."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid artifact reference")
    parts = path.parts
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    identities: list[tuple[int, int]] = []
    try:
        cur_fd = os.open(parts[0], dir_flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT, errno.ENXIO}:
            raise ValueError("invalid artifact reference") from None
        raise
    try:
        st = os.fstat(cur_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError("invalid artifact reference")
        ident = (st.st_dev, st.st_ino)
        if expected_identities is not None:
            if len(expected_identities) != len(parts) or ident != expected_identities[0]:
                raise ValueError("invalid artifact reference")
        identities.append(ident)
        for idx, part in enumerate(parts[1:], start=1):
            if part in ("", ".", ".."):
                raise ValueError("invalid artifact reference")
            try:
                next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT, errno.ENXIO}:
                    raise ValueError("invalid artifact reference") from None
                raise
            os.close(cur_fd)
            cur_fd = next_fd
            st = os.fstat(cur_fd)
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError("invalid artifact reference")
            ident = (st.st_dev, st.st_ino)
            if expected_identities is not None and ident != expected_identities[idx]:
                raise ValueError("invalid artifact reference")
            identities.append(ident)
    except BaseException:
        os.close(cur_fd)
        raise
    return cur_fd, tuple(identities)


class _DiscoveryOutputAdapter:
    """Project in-process discovery outputs before the shared executor receipts.

    Subprocess Hunter already writes its private producer handoff. In-process
    adapters can supply operational observations directly; neither path may
    write raw observations into the canonical public tool output.
    """

    def __init__(self, executor):
        self.executor = executor

    @property
    def timeout_seconds(self):
        return self.executor.timeout_seconds

    @timeout_seconds.setter
    def timeout_seconds(self, value):
        self.executor.timeout_seconds = value

    def terminate(self):
        # Host cancellation can arrive while the discovery adapter is installed.
        return self.executor.terminate()

    def __call__(self, task):
        from python_identity_discovery import public_export, publish_discovery
        execution = self.executor(task)
        result = execution.get("result") if isinstance(execution, dict) else None
        output = result.get("output") if isinstance(result, dict) else None
        try:
            report = json.loads(output) if isinstance(output, str) else output
        except ValueError:
            # Preserve non-JSON failures and their measured request receipts.
            return execution
        if isinstance(report, dict) and isinstance(result, dict):
            safe = public_export(report)
            states = report.get("identity_discovery_state", {})
            from python_identity_discovery import CONTEXT_ENV
            expected_raw = os.environ.get(CONTEXT_ENV)
            if expected_raw and isinstance(states, dict):
                # An actual Hunter producer may already have signed its exact private
                # pipeline; only publish projected subprocess output if absent.
                expected = json.loads(expected_raw)
                if expected.get("result_path") and not Path(expected["result_path"]).exists():
                    publish_discovery(states, safe, operational_report=report)
            if safe != report:
                execution = {**execution, "result": {**result, "output": safe}}
        return execution


class PythonBroker(HostBroker):
    """Call MCP directly; native dispatch/gate/file-writing are not model APIs."""

    def __init__(self, *, workflow_sender=None, **kwargs):
        raw_workdir = kwargs.get("workdir")
        if raw_workdir is None:
            raise ValueError("invalid workdir root")
        raw_path = Path(os.fspath(raw_workdir))
        if ".." in raw_path.parts:
            raise ValueError("invalid workdir root")
        if not raw_path.is_absolute():
            raw_path = Path(os.getcwd()) / raw_path
        authorized_workdir = Path(os.path.abspath(os.fspath(raw_path)))
        try:
            workdir_fd, chain_identities = _open_anchored_dir(authorized_workdir)
        except ValueError:
            raise ValueError("invalid workdir root") from None
        fd_box: list[int | None] = [workdir_fd]
        try:
            super().__init__(**kwargs)
        except BaseException:
            _close_fd_box(fd_box)
            raise
        if self._workdir != authorized_workdir:
            _close_fd_box(fd_box)
            raise ValueError("invalid workdir root")
        self._authorized_workdir = authorized_workdir
        self._authorized_chain_identities = chain_identities
        self._workdir_fd: int | None = workdir_fd
        self._workdir_fd_box = fd_box
        self._workdir_finalizer = weakref.finalize(self, _close_fd_box, fd_box)
        self.runtime_policy = PythonRuntimePolicy(self.budget)
        self.results = []
        self.references = {}
        self.advertised_tools = None
        self.workflow_sender = workflow_sender
        self.workflow_bindings = {}
        self.branch_handoffs = {}
        self.read_progress = {}
        # Host-only map. Never register private references in model archives or
        # put them in results/context rows (which the model can page through).
        self.private_discovery_sources = {}

    @property
    def workdir(self):
        return self._authorized_workdir

    @workdir.setter
    def workdir(self, value):
        raise AttributeError("PythonBroker workdir is immutable")

    def _close_workdir_fd(self):
        finalizer = getattr(self, "_workdir_finalizer", None)
        if finalizer is not None:
            finalizer()
        self._workdir_fd = None

    def close(self):
        try:
            super().close()
        finally:
            self._close_workdir_fd()

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
        if isinstance(body, dict) and body.get("stream"):
            raise ValueError("Python solver requires buffered JSON")
        tools = body.get("tools") if isinstance(body, dict) else None
        worker_call = (
            isinstance(tools, list)
            and bool(tools)
            and not any(row.get("function", {}).get("name") == "task" for row in tools)
        )
        if isinstance(body, dict) and "tools" in body:
            body = {
                **body,
                "tools": compact_tools(
                    body["tools"],
                    description_limit=TOOL_DESCRIPTION_LIMIT,
                    strip_annotations=True,
                ),
            }

        def prepare_request(req_body, metrics):
            active = getattr(getattr(self, "tasks", None), "active_spec", None)
            projection = None
            if worker_call:
                req_body, runtime_info, projection = self.project_runtime_context(
                    req_body, active, None
                )
            else:
                runtime_info = self.runtime_policy.prepare(
                    None, prompt_bound(provider_json(req_body))[0]
                )
            if projection is not None:
                metrics["context_projection"] = projection
            wire = runtime_allowance_request(
                req_body, runtime_info, instruction=PYTHON_ALLOWANCE_INSTRUCTION
            )
            if (
                len(provider_json(wire["messages"])) > MAX_CONTEXT_BYTES
                or prompt_bound(provider_json(wire))[0] > MAX_PROMPT_TOKENS
            ):
                raise BudgetError("context_limit_exhausted")
            return wire, runtime_info, runtime_info["request_token_allowance"]

        return self.provider_transport.complete(
            body,
            prepare_request=prepare_request,
            runtime_policy=self.runtime_policy,
            task_spec_id=getattr(
                getattr(getattr(self, "tasks", None), "active_spec", None),
                "id",
                None,
            ),
            minimum_output_tokens=MIN_OUTPUT_TOKENS,
        )

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
        from python_identity_discovery import public_export
        context = public_export(context)
        if context.get('discovery'):
            # A prior crawler/summary may have no discovery-envelope marker.
            # It is navigation data here, not operational host request context.
            from cco_hunter_core.request_context import public_validator_report
            context['discovery'] = public_validator_report(context['discovery'])
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
                    projected['coverage_gaps'] = compact_gaps(projected.get('coverage_gaps', []))
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
                        {**{key: value for key, value in step.items() if key != 'goal'},
                         **({'goal': str(step['goal'])[:160]} if isinstance(step.get('goal'), str) and step['goal'] else {})}
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
                    if spec.phase in {'recon', 'access', 'enum', 'report'}:
                        # Keep semantic cards and fresh evidence readable. A
                        # compact workflow tool set retains discovery, session
                        # checks and validators even before the first read.
                        has_traversal_cards = any(
                            isinstance(card, dict)
                            and (card.get('vector') == 'file-access' or card.get('tool') == 'validator_validate_path_traversal')
                            for card in (context.get('candidate_cards') or [])
                        )
                        reading_tools = {READ_TOOL, SUMMARY_TOOL, SESSION_CHECK_TOOL,
                                           COVERAGE_TOOL, 'hunter_run_web_loop', CRAWL_TOOL,
                                           COMPILED_WORKFLOW_TOOL, 'validator_validate_sqli',
                                           'validator_validate_ssti',
                                           'validator_validate_idor',
                                           'validator_validate_auth_bypass', 'validator_validate_open_redirect'}
                        if has_traversal_cards:
                            reading_tools.add('validator_validate_path_traversal')
                        if spec.phase in {'recon', 'enum'}:
                            reading_tools |= {
                                'kali-tools_curl_request',
                                'kali-tools_compose_js_routes',
                                'kali-tools_discover_web_surface',
                            }
                        candidate['tools'] = [row for row in candidate['tools']
                                                if row['function']['name'] in reading_tools]
                    if (recent and recent[-1].get('tool') == READ_TOOL
                            and len(recent[-1].get('result', {}).get('text', '')) > 1000):
                        # Page-first projection retains every core capability,
                        # but removes redundant indexes and optional arguments
                        # that the host fills canonically for candidate selection.
                        projected['candidate_cards'] = page_cards(projected.get('candidate_cards', []))
                        if spec.phase in {'access', 'report'}:
                            # The host drives validation/closure here; while a
                            # full page is in context, step IDs are enough and
                            # the freed bytes keep read_artifact advertised.
                            projected['task_spec']['steps'] = [
                                {key: value for key, value in step.items() if key != 'goal'}
                                for step in projected['task_spec']['steps']]
                        if projected.get('discovery_frontier'):
                            projected['discovery_frontier'] = compact_frontier(projected['discovery_frontier'])
                        projected.pop('older_results', None)
                        projected.pop('older_index_ref', None)
                        # Exact safe binding/check maps remain in the archived
                        # context. The vault schema still advertises the exact
                        # lookup target/identities; no session authority changes.
                        projected.pop('session_bindings', None)
                        projected.pop('registered_session_checks', None)
                        has_traversal_cards = any(
                            isinstance(card, dict) and card.get('vector') == 'file-access'
                            for card in (context.get('candidate_cards') or [])
                        )
                        trimmed_tools = {'validator_validate_open_redirect', 'validator_validate_auth_bypass'}
                        if not has_traversal_cards:
                            trimmed_tools.add('validator_validate_path_traversal')
                        candidate['tools'] = [row for row in candidate['tools'] if row['function']['name'] not in trimmed_tools]
                        latest = projected['recent_results'][-1]
                        if latest.get('result', {}).get('content_ref'):
                            latest.pop('content_ref', None)  # Exact wrapper remains in context_archive_ref.
                        if not projected.get('coverage_gap_count'):
                            projected.pop('coverage_gap_archive_ref', None)
                    if (not spec.references and not spec.compiled_workflows
                            and (spec.phase == 'access' or recent and recent[-1].get('tool') == READ_TOOL
                                 and len(recent[-1].get('result', {}).get('text', '')) > 1000)):
                        # Candidate selection needs the slice keys, not every
                        # optional Hunter knob. The solver executes canonical
                        # bounded defaults; preserve required schema constraints.
                        # Do this before the first access turn too, so a large
                        # catalog alone cannot force premature summary-only mode.
                        fields = {'hunter_run_web_loop': {'target', 'live', 'session_bindings', 'validation_profile'},
                                   COVERAGE_TOOL: {'target', 'campaign_id'},
                                   'validator_validate_sqli': {'target_url', 'param', 'method', 'carrier', 'boolean_only'},
                                   'validator_validate_ssti': {'target_url', 'param', 'method', 'carrier'},
                                   'validator_validate_path_traversal': {'target_url', 'param', 'method', 'carrier'}}
                        for tool in candidate['tools']:
                            name = tool['function']['name']
                            params = tool['function']['parameters']
                            if name in fields and params.get('properties'):
                                keep = fields[name] | set(params.get('required', []))
                                params['properties'] = {key: value for key, value in params['properties'].items()
                                                        if key in keep}
                                params['additionalProperties'] = False
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
                    unfinished: dict[str, Any] = {}
                    frontier = projected.get('discovery_frontier')
                    if isinstance(frontier, dict) and isinstance(frontier.get('counts'), dict):
                        counts = frontier['counts']
                        pending_info = {
                            k: int(counts.get(k, 0) or 0)
                            for k in ('pending', 'dispatched', 'blocked', 'indeterminate')
                            if int(counts.get(k, 0) or 0) > 0
                        }
                        if pending_info:
                            unfinished['discovery'] = pending_info
                    cards = projected.get('candidate_cards') or []
                    candidate_count = int(projected.get('candidate_count') or 0)
                    untested_cards = [
                        card for card in cards
                        if isinstance(card, dict) and card.get('validation_state') != 'TESTED'
                    ]
                    if candidate_count and (untested_cards or len(cards) < candidate_count):
                        unfinished['candidates'] = {
                            'total': candidate_count,
                            'untested_in_view': len(untested_cards),
                        }
                    gap_count = int(projected.get('coverage_gap_count') or 0)
                    if gap_count:
                        unfinished['coverage_gaps'] = gap_count
                    task = projected['task_spec']
                    task = {key: task[key] for key in ('id', 'phase', 'target', 'steps')}
                    task['steps'] = [
                        {**{key: value for key, value in step.items() if key != 'goal'},
                         **({'goal': str(step['goal'])[:80]} if isinstance(step.get('goal'), str) and step['goal'] else {})}
                        for step in task['steps']]
                    compact_summary_frontier = (
                        compact_frontier(frontier, max_items=SUMMARY_FRONTIER_LIMIT, max_bytes=SUMMARY_FRONTIER_BYTES)
                        if isinstance(frontier, dict) else None
                    )
                    projected = {key: projected[key] for key in
                                   ('schema', 'context_archive_ref', 'recent_results', 'summary_feedback',
                                    'candidate_cards', 'candidate_count', 'coverage_gaps',
                                    'coverage_gap_count', 'coverage_gap_archive_ref') if key in projected}
                    if compact_summary_frontier is not None:
                        projected['discovery_frontier'] = compact_summary_frontier
                    projected['unfinished_work'] = {'has_unfinished': bool(unfinished), **unfinished}
                    projected['task_spec'] = task
            candidate['messages'][1]['content'] = provider_json(projected).decode()
            closing_projected = projected
            if level < 3 and any(row.get('tool') == READ_TOOL and 'text' in row.get('result', {})
                                 for row in projected.get('recent_results', [])):
                # Closing turns omit transient read_artifact page text (see level 3).
                closing_projected = copy.deepcopy(projected)
                for row in closing_projected.get('recent_results', []):
                    if row.get('tool') == READ_TOOL and 'text' in row.get('result', {}):
                        row['result'].pop('text')
                        row['result']['text_archived'] = True
            closing_messages = candidate['messages'] if closing_projected is projected else [
                candidate['messages'][0],
                {**candidate['messages'][1], 'content': provider_json(closing_projected).decode()},
            ]
            closing = {**candidate, 'messages': closing_messages,
                       'tools': [row for row in candidate.get('tools', [])
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
            wire = runtime_allowance_request(
                candidate, info, instruction=PYTHON_ALLOWANCE_INSTRUCTION
            )
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

    _HOST_ARCHIVE_LABELS = frozenset({
        "tool-result",
        "index",
        "coverage-gaps",
        "invalid-summary",
        "provider-context",
        "validator",
        "handoff",
        "branch-handoff",
    })

    def archive(self, value, label="tool-result"):
        from python_identity_discovery import public_export
        value = public_export(value)
        raw = provider_json(value)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise ArchiveSizeError("archive size limit exceeded")
        digest = hashlib.sha256(raw).hexdigest()
        # Preserve fixed host-internal labels while hashing non-host labels
        # so custom caller labels never leak private metadata or bloat refs.
        raw_label = str(label)
        safe_label = (raw_label if raw_label in self._HOST_ARCHIVE_LABELS
                      else hashlib.sha256(raw_label.encode()).hexdigest()[:16])
        relative = f"context-archive/{safe_label}-{digest}.json"
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

    def _read_reference_bytes(self, ref):
        """Bounded, confined, non-blocking regular-file read for a registered archive."""
        if not isinstance(ref, dict):
            raise ValueError("unknown artifact reference")
        rel = ref.get("path")
        if not isinstance(rel, str) or not rel or self.references.get(rel) != ref:
            raise ValueError("unknown artifact reference")
        expected_bytes = ref.get("bytes")
        expected_sha = ref.get("sha256")
        if (type(expected_bytes) is not int or not 0 <= expected_bytes <= MAX_ARCHIVE_BYTES
                or not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha)):
            raise ValueError("invalid artifact reference")
        if rel.startswith("/") or "\\" in rel or "\x00" in rel:
            raise ValueError("invalid artifact reference")
        parts = rel.split("/")
        if any(part in ("", ".", "..") for part in parts):
            raise ValueError("invalid artifact reference")
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        cur_fd, _identities = _open_anchored_dir(
            self._authorized_workdir,
            expected_identities=self._authorized_chain_identities,
        )
        try:
            if self._workdir_fd is not None:
                anchored_st = os.fstat(self._workdir_fd)
                opened_st = os.fstat(cur_fd)
                if (opened_st.st_dev, opened_st.st_ino) != (anchored_st.st_dev, anchored_st.st_ino):
                    raise ValueError("invalid artifact reference")
            for part in parts[:-1]:
                next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
                os.close(cur_fd)
                cur_fd = next_fd
            fd = os.open(parts[-1], file_flags, dir_fd=cur_fd)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENOENT, errno.ENXIO}:
                raise ValueError("invalid artifact reference") from None
            raise
        finally:
            os.close(cur_fd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("artifact reference is not a regular file")
            if st.st_size > MAX_ARCHIVE_BYTES:
                raise ValueError("artifact reference exceeds size limit")
        except BaseException:
            os.close(fd)
            raise
        with os.fdopen(fd, "rb") as handle:
            raw = handle.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES or len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest() != expected_sha:
            raise ValueError("artifact reference changed")
        return raw

    def read_reference(self, ref):
        """Bounded hash-checked exact bytes; no mtime-only integrity shortcuts."""
        return json.loads(self._read_reference_bytes(ref))

    def view(self, value, label="tool-result"):
        from python_identity_discovery import public_export
        value = public_export(value)
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
            from cco_surface_core import session_store
            if (session_store.get_session(target, identity) is not None
                    and session_store.verified_session(target, identity) is None):
                pre_view = self.invoke(SESSION_CHECK_TOOL, {"target": target, "identity": identity})
                pre_value = pre_view["result"]
                if (not isinstance(pre_value, dict) or pre_value.get("status") != "fresh"
                        or pre_value.get("error") or pre_value.get("execution_failed")
                        or session_store.verified_session(target, identity) is None):
                    self.runtime_policy.record_result(spec, tool, None, "denied")
                    raise SessionBindingError()
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
                path_arg = args.get("path")
                ref = self.references.get(path_arg) if isinstance(path_arg, str) else None
                if ref is None:
                    raise ValueError("unknown artifact reference")
                raw = self._read_reference_bytes(ref)
                offset, size = args.get("offset", 0), args.get("limit", 3000)
                if type(offset) is not int or offset < 0 or type(size) is not int or not 1 <= size <= 3000:
                    raise ValueError("invalid bounded artifact range")
                decoded = raw.decode()
                chunk = decoded[offset:offset + size]
                end = min(len(decoded), offset + len(chunk))
                key = spec.id + ":" + ref["sha256"]
                progress = self.read_progress.setdefault(key, {"ranges": [], "stalls": 0})
                ranges = progress["ranges"]
                useful = bool(chunk) and not any(start <= offset and end <= stop for start, stop in ranges)
                progress["stalls"] = 0 if useful else progress["stalls"] + 1
                if progress["stalls"] >= 2:
                    value = {"content_ref": ref, "offset": offset, "eof": end >= len(decoded),
                             "status": "NOT TESTED", "reason_code": "archive_read_no_progress"}
                else:
                    ranges.append([offset, end])
                    merged: list[list[int]] = []
                    for start, stop in sorted(ranges):
                        if merged and start <= merged[-1][1]:
                            merged[-1][1] = max(stop, merged[-1][1])
                        else:
                            merged.append([start, stop])
                    progress["ranges"] = merged
                    value = {"content_ref": ref, "offset": offset, "text": chunk,
                             "next_offset": end if end < len(decoded) else None, "eof": end >= len(decoded)}
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
            from python_identity_discovery import (CONTEXT_ENV, STATE_ENV,
                                                   prepare_discovery, prepare_invocation,
                                                   seal_discovery)
            discovery_context = os.environ.pop(CONTEXT_ENV, None)
            discovery_state = os.environ.pop(STATE_ENV, None)
            prepared_state_path = None
            expected_discovery = None
            try:
                if (tool == "hunter_run_web_loop" and spec.phase == "access" and not spec.references
                        and not spec.compiled_workflows and args.get("live") is True
                        and args.get("blind_discovery") is True and args.get("target") == spec.target):
                    self._check_handoff(spec)
                    prepared_state_path = prepare_discovery(self, spec, args)
                    expected_discovery = json.loads(os.environ[CONTEXT_ENV])
                elif tool == "hunter_run_web_loop":
                    expected_discovery = prepare_invocation(self, spec, args)
                if tool == SESSION_CHECK_TOOL and {"target": args.get("target"),
                        "identity": args.get("identity", "anon")} not in self.session_checks(spec):
                    # Do not silently rewrite an endpoint into a session target.
                    # Reject before policy/egress and charge the attempted call
                    # to the same allowance and consecutive-failure brake.
                    self.runtime_policy.check_tool(spec, tool)
                    raise SessionBindingError()
                if tool == "hunter_run_web_loop":
                    with self.lock:
                        tool_executor: Any = self.tool_executor
                        executor = tool_executor.executor
                        tool_executor.executor = _DiscoveryOutputAdapter(executor)
                        try:
                            emitted = self.call_tool(group, name, args)
                        finally:
                            tool_executor.executor = executor
                    if expected_discovery is not None and not emitted.get("isError") and len(self.tools) > before:
                        receipt_path = Path(self.tools[-1]["artifact"])
                        receipt = json.loads(receipt_path.read_bytes())
                        exec_payload = receipt.get("execution")
                        if (not receipt.get("error") and isinstance(exec_payload, dict)
                                and not exec_payload.get("execution_failed")):
                            report = json.loads(emitted["content"][0]["text"])
                            seal_discovery(self, spec, args, report, receipt_path, expected_discovery)
                else:
                    emitted = self.call_tool(group, name, args)
            except ValueError:
                # Policy denials before execution still participate in the brake.
                if len(self.tools) == before:
                    self.runtime_policy.record_result(spec, tool, None, "denied")
                raise
            finally:
                os.environ.pop(CONTEXT_ENV, None)
                os.environ.pop(STATE_ENV, None)
                if prepared_state_path is not None:
                    try:
                        if not prepared_state_path.is_symlink() and prepared_state_path.exists():
                            prepared_state_path.unlink()
                    except OSError:
                        pass
                if discovery_context is not None:
                    os.environ[CONTEXT_ENV] = discovery_context
                if discovery_state is not None:
                    os.environ[STATE_ENV] = discovery_state
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
        if tool == SESSION_CHECK_TOOL:
            # Scheduling age and host-private verified vault linkage only;
            # never project credentials, secret_ref, or raw claims.
            row["session_check_observed_at"] = time.time()
            if (isinstance(value, dict) and value.get("status") == "fresh"
                    and not value.get("error") and not value.get("execution_failed")
                    and value.get("target") == args.get("target")
                    and value.get("identity") == args.get("identity")):
                from cco_surface_core import session_store
                verified = session_store.verified_session(args["target"], args["identity"])
                if (isinstance(verified, dict)
                        and isinstance(verified.get("check_id"), str) and verified["check_id"]
                        and isinstance(verified.get("secret_ref"), str) and verified["secret_ref"]):
                    row["session_check_fingerprint"] = session_store.check_fingerprint(
                        args["target"], args["identity"], entry=verified
                    )
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

    def private_discovery_report_for_execution(self, spec, execution_path, public_output=None):
        """Resolve signed private operational report for one measured receipt."""
        from python_identity_discovery import _reference, _read_reference, _source_observation
        path = str(execution_path)
        private_ref = self.private_discovery_sources.get(path)
        if private_ref is None:
            raise ValueError("private discovery report provenance unavailable")
        source = {"execution_reference": _reference(Path(path)), "private_reference": private_ref}
        receipt = _read_reference(source["execution_reference"])
        if public_output is None:
            public_output = ((receipt.get("execution") or {}).get("result") or {}).get("output")
            if isinstance(public_output, str):
                public_output = json.loads(public_output)
        observation = _source_observation(source, spec.to_dict(), public_output, receipt)
        return copy.deepcopy(observation["operational_report"])

    def private_discovery_report(self, spec, content_ref):
        """Host-only exact pipeline after public archive/receipt/producer checks.

        This is deliberately not a model tool or an archive-reader mode. Public
        read_reference/read_artifact never hydrate operational routes or markers.
        """
        from evidence_trust import canonical_bytes
        from python_identity_discovery import _reference, _read_reference, _source_observation
        public = self.read_reference(content_ref)
        for row in self.results:
            if (row["spec_id"] != spec.id or row["tool"] != "hunter_run_web_loop"
                    or row["content_ref"] != content_ref):
                continue
            for execution in self.tools:
                if (execution.get("origin") != "solver" or execution.get("task_spec_id") != spec.id
                        or execution.get("tool") != "hunter_run_web_loop"):
                    continue
                path = str(execution["artifact"])
                private_ref = self.private_discovery_sources.get(path)
                if private_ref is None:
                    continue
                source = {"execution_reference": _reference(Path(path)), "private_reference": private_ref}
                receipt = _read_reference(source["execution_reference"])
                if canonical_bytes(receipt.get("arguments")) != canonical_bytes(row["arguments"]):
                    continue
                try:
                    observation = _source_observation(source, spec.to_dict(), public, receipt)
                except (ValueError, OSError, TypeError, KeyError):
                    continue
                return copy.deepcopy(observation["operational_report"])
        raise ValueError("private discovery report provenance unavailable")

    def validation_attempts(self, spec):
        """IDs come only from executed validation tools and current signatures."""
        from brain import _VALIDATOR_VECTOR_TYPES, _VALIDATOR_VECTOR_ALIASES, runtime_root
        validator_path = str(runtime_root() / "mcp-servers/mcp-validator")
        if validator_path not in sys.path:
            sys.path.append(validator_path)
        from cco_validator_core import artifact_is_current, load_validation, normalize_finding_type
        from python_identity_discovery import public_export
        attempts = {}
        executions = {}
        owners: dict[str, str] = {}
        for execution in self.tools:
            if (execution.get("origin") != "solver" or not execution.get("task_spec_id")
                    or not (execution["tool"] == "hunter_run_web_loop" or execution["tool"].startswith("validator_validate_"))):
                continue
            receipt = json.loads(Path(execution["artifact"]).read_bytes())
            result = receipt.get("execution") or {}
            if receipt.get("error") or result.get("execution_failed"):
                continue
            value = result.get("result", {}).get("output")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    continue
            if not isinstance(value, dict):
                continue
            # Join only the exact safe projection of a measured private receipt.
            # Direct signed records stay untouched; public route templates are
            # never used as operational request/scoring context.
            key = provider_json([execution["task_spec_id"], execution["tool"], receipt["arguments"], public_export(value)])
            executions[key] = execution["artifact"]
            for item in [value, *(value.get("validations") or [])]:
                if isinstance(item, dict) and isinstance(item.get("validation_id"), str):
                    owners.setdefault(item["validation_id"], execution["task_spec_id"])
        for row in self.results:
            if row["spec_id"] != spec.id or not (row["tool"] == "hunter_run_web_loop"
                    or row["tool"].startswith("validator_validate_")):
                continue
            ref = row["content_ref"]
            value = self.read_reference(ref)
            if not isinstance(value, dict) or value.get("execution_failed") or value.get("error"):
                continue
            execution_path = executions.get(provider_json([spec.id, row["tool"], row["arguments"], value]))
            if execution_path is None:
                continue
            if row["tool"] == "hunter_run_web_loop" and str(execution_path) in self.private_discovery_sources:
                from python_identity_discovery import _reference, _read_reference, _source_observation
                source = {"execution_reference": _reference(Path(execution_path)),
                          "private_reference": self.private_discovery_sources[str(execution_path)]}
                try:
                    observation = _source_observation(source, spec.to_dict(), value,
                                                      _read_reference(source["execution_reference"]),
                                                      require_fresh=False)
                except (ValueError, OSError, TypeError, KeyError):
                    continue
                value = observation["operational_report"]
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
                # A signed ID still has to describe this executed request, not
                # an unrelated signed record from another task/parameter.
                if owners.get(candidate["validation_id"]) != spec.id:
                    continue
                context = record.get("execution_context", {})
                args = row["arguments"]
                if row["tool"].startswith("validator_validate_"):
                    expected_kind = row["tool"].removeprefix("validator_validate_")
                    aliases = {"sqli": "SQL Injection", "ssti": "SSTI"}
                    if expected_kind in aliases and kind != normalize_finding_type(aliases[expected_kind]):
                        continue
                    if not context and row["tool"] in {"validator_validate_sqli", "validator_validate_ssti"}:
                        context = self.direct_request_context(record, args)
                    if row["tool"] in {"validator_validate_sqli", "validator_validate_ssti"}:
                        # Read-only host slices require a complete signed (or
                        # signed-wire-derived) request context and the selected
                        # deterministic oracle, not just a valid artifact ID.
                        profile = ("readonly_sqli_boolean" if row["tool"] == "validator_validate_sqli"
                                   else "readonly_ssti_arithmetic")
                        if (args.get("method", "GET") == "GET" and args.get("carrier", "query") == "query"
                                and (row["tool"] != "validator_validate_sqli" or args.get("boolean_only") is True)):
                            if (record.get("oracle") != PROFILES[profile][2]
                                    or not {"param", "method", "carrier", "identity"} <= context.keys()
                                    or context.get("identity") not in {"anon", "anonymous"}):
                                continue
                    if (record["target"] != args.get("target_url")
                            or context.get("param", "") != args.get("param", "")
                            or context.get("method", "GET") != args.get("method", "GET")
                            or context.get("carrier", "query") != args.get("carrier", "query")):
                        continue
                elif candidate is not value:
                    fields = ("url", "method", "vuln_class", "operation_id", "resource_owner", "identity", "param", "carrier")
                    if (record["target"] != candidate.get("url") or any(
                            candidate.get(key) != context.get(key) for key in fields if key in candidate)):
                        continue
                else:
                    # Hunter's evidence contract is its observed validation
                    # queue, not a top-level scalar copied from another run.
                    continue
                if vector == "authz-idor" and not authorization_controls_complete(record):
                    continue
                attempts[record["validation_id"]] = {"vector": vector, "record": record,
                    "tool": row["tool"],
                    "execution_context": context,
                    "source_artifact": ref["path"], "source_sha256": ref["sha256"]}
        return list(attempts.values())

    def profile_eligibility(self, spec, url: str, param: str, carrier: str, profile: str) -> dict[str, Any]:
        """Evaluate private-policy eligibility inside the trusted host boundary.

        Exposes only an eligibility boolean and controlled reason code, never
        file names, policy fragments, markers, or suggested routes.
        """
        if profile != "readonly_traversal_application_files":
            return {"eligible": True, "reason_code": ""}
        spec_origin = urlsplit(spec.target)
        cand_origin = urlsplit(url)
        if (cand_origin.scheme, cand_origin.netloc) != (spec_origin.scheme, spec_origin.netloc):
            return {"eligible": False, "reason_code": "traversal_policy_invalid"}
        validator_path = str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator")
        if validator_path not in sys.path:
            sys.path.append(validator_path)
        from cco_validator_core.traversal import check_traversal_policy_eligibility

        rule: Any = None
        policy_map = getattr(self.engine, "program_policy", None)
        if isinstance(policy_map, dict):
            rule = policy_map.get("path_traversal")
        elif os.environ.get("CCO_PROGRAM_POLICY_FILE"):
            try:
                from policy_engine import PolicyEngine
                engine = PolicyEngine()
                rule = engine.program_policy.get("path_traversal")
            except (ValueError, OSError, TypeError):
                return {"eligible": False, "reason_code": "traversal_policy_invalid"}
        else:
            return {"eligible": False, "reason_code": "traversal_policy_not_declared"}

        permits = lambda candidate_url: (
            urlsplit(candidate_url).scheme == spec_origin.scheme
            and urlsplit(candidate_url).netloc == spec_origin.netloc
        )
        if os.environ.get("CCO_SCOPE_FILE"):
            try:
                from policy_engine import ScopeResolver
                resolver = ScopeResolver(scope_file=os.environ.get("CCO_SCOPE_FILE"))
                permits = lambda candidate_url: (
                    urlsplit(candidate_url).scheme == spec_origin.scheme
                    and urlsplit(candidate_url).netloc == spec_origin.netloc
                    and bool(resolver.permits_url(candidate_url))
                )
            except (ValueError, OSError, TypeError):
                return {"eligible": False, "reason_code": "traversal_policy_invalid"}
        return check_traversal_policy_eligibility(rule, url, param, carrier, permits)

    def signed_completions(self, spec) -> list[dict[str, Any]]:
        """Return verified v1 signed_completion envelopes from executed host tool receipts."""
        from signed_completion import verify_signed_completion
        validator_path = str(Path(__file__).resolve().parents[1] / "mcp-servers/mcp-validator")
        if validator_path not in sys.path:
            sys.path.append(validator_path)
        from cco_validator_core.evidence import artifact_is_current, current_scope_revision, load_validation

        try:
            expected_scope = current_scope_revision() if os.environ.get("CCO_SCOPE_FILE") else None
        except (ValueError, OSError):
            expected_scope = None

        executions: dict[bytes, tuple[str, dict[str, Any]]] = {}
        for execution in self.tools:
            if (execution.get("origin") != "solver" or execution.get("task_spec_id") != spec.id
                    or not (execution["tool"] == "hunter_run_web_loop" or execution["tool"].startswith("validator_validate_"))):
                continue
            receipt = json.loads(Path(execution["artifact"]).read_bytes())
            result = receipt.get("execution") or {}
            if receipt.get("error") or result.get("execution_failed"):
                continue
            value = result.get("result", {}).get("output")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    continue
            if not isinstance(value, dict):
                continue
            from python_identity_discovery import public_export
            key = provider_json([execution["task_spec_id"], execution["tool"], receipt["arguments"], public_export(value)])
            executions[key] = (execution["artifact"], value)

        verified: list[dict[str, Any]] = []
        for row in self.results:
            if row["spec_id"] != spec.id or not (
                row["tool"] == "hunter_run_web_loop" or row["tool"].startswith("validator_validate_")
            ):
                continue
            ref = row["content_ref"]
            try:
                value = self.read_reference(ref)
            except (ValueError, OSError, TypeError):
                continue
            if not isinstance(value, dict) or value.get("execution_failed") or value.get("error"):
                continue
            exec_info = executions.get(provider_json([spec.id, row["tool"], row["arguments"], value]))
            if exec_info is None:
                continue
            execution_path, raw_output = exec_info
            envelopes: list[dict[str, Any]] = []
            if row["tool"] == "hunter_run_web_loop":
                report = raw_output
                if str(execution_path) in self.private_discovery_sources:
                    try:
                        report = self.private_discovery_report_for_execution(spec, execution_path, value)
                    except (ValueError, OSError, TypeError, KeyError):
                        continue
                if (
                    not isinstance(report, dict)
                    or report.get("ok") is not True
                    or report.get("errors")
                    or report.get("stopped")
                ):
                    continue
                if not report.get("confirmed"):
                    if isinstance(report.get("signed_completion"), dict):
                        envelopes.append(report["signed_completion"])
                    if isinstance(report.get("signed_completions"), list):
                        envelopes.extend(e for e in report["signed_completions"] if isinstance(e, dict))
                for val_item in report.get("validations") or []:
                    if isinstance(val_item, dict) and val_item.get("validation_id"):
                        rec = load_validation(str(val_item["validation_id"]))
                        if (rec and rec.get("verdict") == "UNCONFIRMED"
                                and rec.get("guard", {}).get("transport_ok")
                                and artifact_is_current(rec, expected_target=spec.target)
                                and isinstance(rec.get("signed_completion"), dict)):
                            envelopes.append(rec["signed_completion"])
            else:
                if isinstance(raw_output.get("signed_completion"), dict):
                    envelopes.append(raw_output["signed_completion"])
                vid = raw_output.get("validation_id")
                if isinstance(vid, str) and vid:
                    rec = load_validation(vid)
                    if (rec and rec.get("verdict") == "UNCONFIRMED"
                            and rec.get("guard", {}).get("transport_ok")
                            and artifact_is_current(rec, expected_target=spec.target)
                            and isinstance(rec.get("signed_completion"), dict)):
                        envelopes.append(rec["signed_completion"])
            for env in envelopes:
                ok, payload, _ = verify_signed_completion(
                    env,
                    expected_target=spec.target,
                    expected_scope=expected_scope,
                )
                if ok and payload is not None:
                    verified.append({
                        "payload": payload,
                        "envelope": env,
                        "tool": row["tool"],
                        "source_artifact": ref["path"],
                        "source_sha256": ref["sha256"],
                        "arguments": row["arguments"],
                    })
        return verified

    def direct_request_context(self, record, args):
        """Infer a slice only from signed wire traces, not unsigned tool metadata."""
        target = urlsplit(args.get("target_url", ""))
        try:
            baseline = query_parameters(args.get("target_url", ""))
        except ValueError:
            return {}
        param = args.get("param")
        if not param or param not in baseline or args.get("method", "GET") != "GET" or args.get("carrier", "query") != "query":
            return {}
        probes = record.get("request_evidence", [])
        changed = False
        for probe in probes:
            url = urlsplit(probe.get("request_url", ""))
            try:
                query = query_parameters(probe.get("request_url", ""))
            except ValueError:
                return {}
            if ((url.scheme, url.netloc, url.path) != (target.scheme, target.netloc, target.path)
                    or probe.get("method") != "GET" or not probe.get("transport_ok")
                    or set(query) != set(baseline)
                    or any(query[key] != baseline[key] for key in baseline if key != param)):
                return {}
            changed |= query[param] != baseline[param]
        return {"param": param, "method": "GET", "carrier": "query", "identity": "anon"} if changed else {}

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

    def session_check_evidence(self, spec=None):
        spec = spec or self.tasks.active_spec
        sources = {spec.id, *upstream_ids(spec, self.tasks.specs)} if spec else set()
        checks: dict[str, dict] = {}
        for row in self.results:
            if row.get("spec_id") in sources and row.get("tool") == SESSION_CHECK_TOOL:
                args = row.get("arguments") or {}
                identity = args.get("identity")
                target = args.get("target")
                if not isinstance(identity, str) or not identity or not isinstance(target, str) or not target:
                    continue
                if (row.get("is_error") or not isinstance(row.get("session_check_fingerprint"), str)
                        or not row["session_check_fingerprint"]):
                    checks.pop(identity, None)
                    continue
                value = self.read_reference(row.get("content_ref"))
                if (isinstance(value, dict) and value.get("status") == "fresh"
                        and not value.get("error") and not value.get("execution_failed")
                        and value.get("target") == target and value.get("identity") == identity):
                    checks[identity] = value
                else:
                    checks.pop(identity, None)
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

    def _fresh_task_session_check(self, spec, args):
        from cco_surface_core import session_store
        if not isinstance(args, dict):
            return False
        target = args.get("target")
        identity = args.get("identity")
        if not isinstance(target, str) or not target or not isinstance(identity, str) or not identity:
            return False
        verified = session_store.verified_session(target, identity)
        if not isinstance(verified, dict):
            return False
        if (not isinstance(verified.get("check_id"), str) or not verified["check_id"]
                or not isinstance(verified.get("secret_ref"), str) or not verified["secret_ref"]):
            return False
        try:
            current_fingerprint = session_store.check_fingerprint(target, identity, entry=verified)
        except (OSError, TypeError, ValueError):
            return False
        if not isinstance(current_fingerprint, str) or not current_fingerprint:
            return False
        for row in reversed(self.results):
            if (row.get("spec_id") == spec.id and row.get("tool") == SESSION_CHECK_TOOL
                    and row.get("arguments") == {"target": target, "identity": identity}):
                if row.get("is_error"):
                    return False
                observed_fp = row.get("session_check_fingerprint")
                if (not isinstance(observed_fp, str) or not observed_fp
                        or not hmac.compare_digest(observed_fp, current_fingerprint)):
                    return False
                try:
                    value = self.read_reference(row.get("content_ref"))
                except (ValueError, OSError):
                    return False
                if (not isinstance(value, dict) or value.get("status") != "fresh"
                        or value.get("error") or value.get("execution_failed")):
                    return False
                if value.get("target") != target or value.get("identity") != identity:
                    return False
                if value.get("check_id") is not None and value.get("check_id") != verified["check_id"]:
                    return False
                return True
        return False

    def handoff(self):
        spec = self.tasks.active_spec
        checks = self.session_checks(spec)
        if len(checks) != len(self.tasks.bindings):
            raise HandoffError("handoff_session_binding_invalid")
        pending = [args for args in checks if not self._fresh_task_session_check(spec, args)]
        self.runtime_policy.reserve_handoff(spec, len(pending))
        remaining = min(spec.max_calls, PHASE_CALL_LIMITS[spec.phase]) - self.runtime_policy.tool_calls.get(spec.id, 0)
        if remaining < len(pending) + 1:
            raise BudgetError("handoff_tool_budget_exhausted")
        self.runtime_policy.host_finalizing.add(spec.id)
        try:
            # Provider turns may exceed the 300-second freshness window. Do
            # real policy-gated, charged checks immediately before handoff;
            # never extend the window or assume setup remains fresh.
            for args in pending:
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
            receipt = copy.deepcopy(self.handoffs["access"])
            if receipt.get("producer_spec_id") == spec.id:
                receipt["snapshots"] = {name: self.archive({"exact_text": Path(name).read_text()}, "branch-handoff")
                                        for name in receipt["files"]}
                self.branch_handoffs[spec.id] = receipt
        finally:
            self.runtime_policy.host_finalizing.discard(spec.id)
            dump(self.private / "runtime-policy.json", self.runtime_policy.snapshot())

    def _check_handoff(self, spec):
        if spec.phase not in {"access", "authz"}:
            return
        sources = set(upstream_ids(spec, self.tasks.specs))
        label = spec.vector or spec.phase
        receipts = [row for ident, row in self.branch_handoffs.items() if ident in sources and label == "access"]
        if len(receipts) > 1:
            raise ValueError("ambiguous declared discovery handoff")
        if receipts:
            from evidence_trust import atomic_write
            receipt = copy.deepcopy(receipts[0])
            # Restore only exact host-sealed bytes for the selected branch. The
            # ordinary handoff gate rechecks summary/pool/session policy below.
            for name, ref in receipt.pop("snapshots").items():
                value = self.read_reference(ref)
                raw = provider_json(value)
                # archive JSON serialization differs from ledger formatting;
                # retain the original digest by storing the original text too.
                if isinstance(value, dict) and set(value) == {"exact_text"}:
                    raw = value["exact_text"].encode()
                if hashlib.sha256(raw).hexdigest() != receipt["files"][name]:
                    raise ValueError("branch handoff snapshot changed")
                atomic_write(Path(name), raw)
            self.handoffs[label] = receipt
        record = self.handoffs.get(label)
        if record and record.get("producer_spec_id") not in sources:
            raise ValueError("handoff producer outside declared dependencies")
        return super()._check_handoff(spec)

    def verified_findings(self, spec):
        """Accept IDs only from actual tools, then use the existing signature gate."""
        from brain import _confirmation_record
        import hypothesis_ledger as hypotheses
        findings = {}
        for item in self.validation_attempts(spec):
            for vector in hypotheses.DEFAULT_VECTORS:
                record, _ = _confirmation_record({"validation_id": item["record"]["validation_id"]}, vector,
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
        sources = set(upstream_ids(spec, self.tasks.specs))
        summaries = [self.tasks.read_summary(s) for s in self.tasks.specs if s.phase == "access" and s.id in sources]
        summary = {"findings": [row for previous in summaries for row in previous.get("findings", [])],
                   "not_tested_reasons": [row for previous in summaries for row in previous.get("not_tested_reasons", [])]}
        reasons = {row["vector"]: row for row in summary.get("not_tested_reasons", [])}
        for finding in summary["findings"]:
            vector = finding["vector"]
            record, _ = _confirmation_record(finding, vector, ledger)
            if record is None:
                raise ValueError("validator receipt became stale")
            if vector == "authz-idor" and not authorization_controls_complete(record):
                raise ValueError("validator receipt missing authorization controls")
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
