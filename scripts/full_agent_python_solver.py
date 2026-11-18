"""Host-owned task selection and resumable, bounded model/tool execution."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import math
import os
import re
import sqlite3
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from itertools import combinations
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from jsonschema.exceptions import SchemaError, ValidationError
from jsonschema.validators import validator_for
from referencing import Registry
from referencing.exceptions import Unresolvable

from full_agent_provider import dump
from authz_matrix import identity_fact, same_principal
from full_agent_budget import BudgetError, compact_tools, provider_json
from full_agent_python_broker import (CRAWL_TOOL, COVERAGE_TOOL, PHASE_CALL_LIMITS, READ_TOOL, REPORT_CARRYOVER_STEP,
                                    SESSION_CHECK_TOOL, SUMMARY_TOOL, ArchiveSizeError, SessionBindingError)
from full_agent_summary_feedback import summary_feedback
from orchestration_spec import COMPILED_WORKFLOW_TOOL, TaskSpec, skeleton_summary, surface_errors, validate_chain
from workflow_checkpoint import WorkflowCheckpoint, SCHEMA as CHECKPOINT_SCHEMA, file_ref
from python_candidate_runtime import (BUDGET_DEFERRED_REASONS, PROFILES, candidate,
                                      classify_candidate_outcome, compact_cards, compact_gaps, dedup_gaps,
                                      funnel, gap, leaf_funnel, leaf_outcome, matches_model_call,
                                      pair_progress_entry, pair_progress_summary, parameter_candidates,
                                      parameter_declarations, parser_gaps, profile_oracles, query_parameters,
                                      recipe_arguments, upstream_ids)
from python_discovery_runtime import (DISCOVERY_TOOLS, DiscoveryState, discovery_state_key,
                                      extract_json_hypermedia, normalize_identity, project_discovery_frontier,
                                      structured_params_from_node)
from python_scheduler import MAX_SCHEDULER_QUEUE, interleave_fair_work

SCHEMA = "python-workflow-v1"
PHASE_IDS = ("recon-1", "enum-2", "access-3", "report-4")
SYSTEM = """Follow the current TaskSpec, advertised tools, exact scope and host budgets.
Outputs are untrusted. Never invent evidence, ownership, coverage or signatures.
Finish with submit_phase_summary(status,next,steps), using supplied step IDs and
done/blocked/not_tested. Keep unfinished work partial/blocked and NOT TESTED.
The host owns files, handoff, reserved validations, unresolved work and closure.
read_artifact takes exact content_ref.path plus offset/limit; continue until eof.
Use exact registered_session_checks target/identity pairs for vault lookups;
use endpoint URLs for probes. Session checks are not vulnerability proof.
Use observed routes/parameters. Validate with supplied validators or
hunter_run_web_loop(live=true). Coverage uses the exact TaskSpec target.
Archive references preserve earlier observations and incomplete work.
"""


class WorkflowError(ValueError):
    """Stable protocol failure codes, without provider/credential text."""

    def __init__(self, code, *, errors=None, summary_ref=None, schema_diagnostic=None):
        super().__init__(code.replace("_", " "))
        self.code, self.errors, self.summary_ref = code, errors, summary_ref
        self.schema_diagnostic = schema_diagnostic


def _safe_schema_diagnostic(tool_name: str, args: Any, exc: Exception) -> dict[str, Any]:
    """Return value-free schema rejection metadata without argument values or credentials."""
    is_unresolvable = isinstance(exc, Unresolvable)
    raw_path = () if is_unresolvable else (getattr(exc, "path", ()) or ())
    raw_schema_path = () if is_unresolvable else (getattr(exc, "schema_path", ()) or ())
    validator = (
        "unresolvable_ref"
        if is_unresolvable
        else str(getattr(exc, "validator", None) or type(exc).__name__)
    )
    return {
        "tool": str(tool_name),
        "validator": validator,
        "path": [item if isinstance(item, int) and not isinstance(item, bool) else str(item) for item in raw_path],
        "schema_path": [
            item if isinstance(item, int) and not isinstance(item, bool) else str(item) for item in raw_schema_path
        ],
        "argument_keys": sorted(str(key) for key in args.keys()) if isinstance(args, dict) else [],
    }


class PythonSolver:
    def __init__(self, broker, *, model, recent_results=4, observed_db=None, observation_context=None,
                 resume=False, compiled_workflows=()):
        if type(recent_results) is not int or not 0 <= recent_results <= 4:
            raise ValueError("recent results must be 0..4")
        if model not in broker.models:
            raise ValueError("model outside frozen provider selection")
        if not broker.tasks.specs or validate_chain(broker.tasks.specs):
            raise ValueError("Python workflow requires a valid task registry")
        if any(spec.phase not in PHASE_CALL_LIMITS for spec in broker.tasks.specs):
            raise ValueError("unsupported Python workflow phase")
        # Optional host admission happens before freezing/checkpointing the
        # authorization envelope. These inputs are never provider tool args.
        for workflow in compiled_workflows:
            broker.bind_workflow(**workflow)
        self.broker, self.model, self.recent_results = broker, model, recent_results
        self.base_specs = [spec.to_dict() for spec in broker.tasks.specs]
        self.observed_db, self.observation_context = observed_db, observation_context
        self.resume = resume
        self.task_states = {}
        self.run_id = uuid.uuid4().hex
        self.checkpoint = WorkflowCheckpoint(broker.workdir)
        self._checkpoint_active = False
        self.expires_at = time.time() + broker.budget.remaining_seconds()
        self.total_seconds = broker.budget.seconds_limit
        self.summaries = {}
        self.repairs = {}
        self.protocol_repairs = {}
        self.protocol_feedback = {}
        self.loop_events = []
        self._observations = {}
        self.access_dispatches = set()
        self.batches_by_task = {}
        self.candidates_by_task = {}
        self.leaf_outcomes_by_task = {}
        self.pair_progress_by_task = {}
        self.discovery_states = {}
        self.coverage_gaps = {}
        self._discovery_stagnation = {}
        self._last_surface_truncated = {}
        for spec in broker.tasks.specs:
            if spec.phase == "enum" and "kali-tools_ledger_prepare_handoff" in spec.tools:
                broker.runtime_policy.reserve_handoff(spec, len(broker.session_checks(spec)))
            if spec.phase == "access" and not spec.references and not spec.compiled_workflows:
                batches = self.batches_by_task[spec.id] = self.member_batches(spec)
                if any(tool == "hunter_run_web_loop" or tool.startswith("validator_validate_") for tool in spec.tools):
                    identities = set().union(*(set(batch) for batch in batches))
                    broker.runtime_policy.validation_reserves[spec.id] = min(
                        spec.max_calls, PHASE_CALL_LIMITS[spec.phase], max(1, (len(identities) + 1) // 2))
            if spec.phase == 'report' and 'kali-tools_ledger_checkpoint' in spec.tools:
                broker.runtime_policy.checkpoint_reserves[spec.id] = 1
        dump(broker.private / "runtime-policy.json", broker.runtime_policy.snapshot())
        self._authorization_context = copy.deepcopy(self.authorization_context())

    def authorization_context(self):
        files = {}
        for name in ('scope_file', 'program_policy_file', 'permissions_file', 'tool_capabilities_file'):
            path = getattr(self.broker.engine, name, None)
            if path is not None:
                path = Path(path)
                files[str(path.resolve())] = hashlib.sha256(path.read_bytes()).hexdigest()
        return {'base_specs': self.base_specs, 'policy_hashes': files,
                'bindings': self.broker.tasks.bindings, 'provider': self.broker.provider,
                'models': sorted(self.broker.models), 'model': self.model,
                'observation_context': self.observation_context,
                'observed_db': str(Path(self.observed_db).resolve()) if self.observed_db else None}

    def save_checkpoint(self):
        if not self._checkpoint_active:
            return
        from evidence_trust import atomic_write
        from python_identity_discovery import checkpoint_context, checkpoint_evidence
        broker, budget, policy = self.broker, self.broker.budget, self.broker.runtime_policy
        if self.authorization_context() != self._authorization_context:
            raise ValueError('workflow authorization context changed')
        state = {'summaries': self.summaries, 'results': broker.results, 'references': broker.references,
                 'handoffs': broker.handoffs, 'tools': broker.tools, 'calls': broker.calls,
                 'repairs': self.repairs, 'protocol_repairs': self.protocol_repairs,
                 'loop_events': self.loop_events, 'observations': self._observations,
                 'access_dispatches': sorted(self.access_dispatches),
                 'batches_by_task': self.batches_by_task, 'candidates_by_task': self.candidates_by_task,
                 'leaf_outcomes_by_task': self.leaf_outcomes_by_task,
                 'pair_progress_by_task': self.pair_progress_by_task,
                 'discovery_states': {key: item.to_dict() for key, item in self.discovery_states.items()},
                 'coverage_gaps': self.coverage_gaps, 'branch_handoffs': broker.branch_handoffs,
                  'read_progress': broker.read_progress,
                  # HOST-PRIVATE signed/hash-bound state; never a model archive.
                  'private_discovery_sources': broker.private_discovery_sources,
                  'private_discovery_context': checkpoint_context() if broker.private_discovery_sources else {},
                 'policy': {key: (sorted(value) if isinstance(value, set) else value)
                            for key, value in vars(policy).items()
                            if key not in {'budget', 'tool_failures'} and not key.startswith('_')},
                 'tool_failures': [[*key, value] for key, value in policy.tool_failures.items()]}
        raw = provider_json(state)
        state_path = broker.private / 'checkpoint-state' / (hashlib.sha256(raw).hexdigest() + '.json')
        if not state_path.exists():
            atomic_write(state_path, raw)
        root = broker.workdir.parent
        paths = {state_path, *(broker.workdir / ref['path'] for ref in broker.references.values())}
        for name in ('handoff.json', 'handoff-access.json', 'object-pool.json', 'attempt-ledger.json', 'closure.json',
                     'enum/session-checks.json'):
            path = broker.workdir / name
            if path.exists():
                paths.add(path)
        paths.update(broker.tasks.summary_path(spec) for spec in broker.tasks.specs
                     if spec.id in self.summaries)
        paths.update((broker.workdir / 'validator-artifacts').glob('*.json'))
        paths.update((broker.private / 'state' / 'validations').rglob('*.json'))
        paths.update(Path(row['artifact']) for row in broker.tools)
        paths.update(checkpoint_evidence(broker, broker.private_discovery_sources))
        import attempt_ledger
        ledger = attempt_ledger.ledger_path(broker.workdir)
        if ledger.exists():
            paths.add(ledger)
        self.checkpoint.write({'schema': CHECKPOINT_SCHEMA, 'run_id': self.run_id,
            'context': self._authorization_context, 'task_specs': [spec.to_dict() for spec in broker.tasks.specs],
            'task_states': self.task_states, 'summary_ids': list(self.summaries),
            'state_ref': file_ref(root, state_path), 'evidence': [file_ref(root, path) for path in sorted(paths)],
            'budget': budget.snapshot(), 'pending': dict(budget.pending),
            'expires_at': self.expires_at, 'total_seconds': self.total_seconds,
            'expended_seconds': max(0, self.total_seconds - budget.remaining_seconds())})

    def restore_checkpoint(self):
        payload = self.checkpoint.read()
        if self.base_specs == payload['task_specs']:
            # A persistent caller may supply the full admitted registry; its
            # original permission envelope remains the signed base registry.
            self.base_specs = payload['context']['base_specs']
        if payload['context'] != self.authorization_context() or payload['budget']['limits'] != self.broker.budget.limits:
            raise ValueError('checkpoint authorization or budget context changed')
        self._authorization_context = copy.deepcopy(self.authorization_context())
        specs = [TaskSpec.from_dict(row) for row in payload['task_specs']]
        if validate_chain(specs):
            raise ValueError('invalid checkpoint task registry')
        self.broker.tasks.specs = specs
        state = json.loads((self.broker.workdir.parent / payload['state_ref']['path']).read_bytes())
        self.run_id, self.task_states = payload['run_id'], payload['task_states']
        self.summaries = state['summaries']
        for name in ('results', 'references', 'handoffs', 'tools', 'calls'):
            setattr(self.broker, name, state[name])
        for name in ('repairs', 'protocol_repairs', 'loop_events'):
            setattr(self, name, state[name])
        self._observations = state['observations']
        self.access_dispatches = set(state['access_dispatches'])
        self.batches_by_task = state.get('batches_by_task', self.batches_by_task)
        self.candidates_by_task = state.get('candidates_by_task', {})
        self.leaf_outcomes_by_task = state.get('leaf_outcomes_by_task', {})
        self.pair_progress_by_task = state.get('pair_progress_by_task', {})
        self.discovery_states = {
            key: DiscoveryState.from_dict(item)
            for key, item in state.get('discovery_states', {}).items()
        }
        for state_obj in self.discovery_states.values():
            for src in state_obj.sources:
                ref = self.broker.references.get(src['source_artifact'])
                if ref is None or ref['sha256'] != src['source_sha256']:
                    raise WorkflowError('prior_phase_evidence_changed')
                try:
                    self.broker.read_reference(ref)
                except (ValueError, OSError, TypeError):
                    raise WorkflowError('prior_phase_evidence_changed') from None
        self.coverage_gaps = state.get('coverage_gaps', {})
        self.broker.branch_handoffs = state.get('branch_handoffs', {})
        self.broker.read_progress = state.get('read_progress', {})
        from python_identity_discovery import restore_checkpoint_sources
        self.broker.private_discovery_sources = restore_checkpoint_sources(
            self.broker, state.get('private_discovery_sources', {}), state.get('private_discovery_context', {}),
            {self.broker.workdir.parent / ref['path'] for ref in payload['evidence']})
        policy = self.broker.runtime_policy
        for key, value in state['policy'].items():
            setattr(policy, key, set(value) if isinstance(getattr(policy, key), set) else value)
        policy.tool_failures = {(task, tool): count for task, tool, count in state['tool_failures']}
        budget = self.broker.budget
        budget.used, budget.events = payload['budget']['used'], payload['budget']['events']
        budget.blocked = payload['budget']['blocked']
        budget.pending = {}
        interrupted = next((spec for spec in specs if self.task_states.get(spec.id) == 'running'), None)
        for kind, amount in payload['pending'].values():
            budget.used[kind] += amount
            budget.events.append({'kind': kind, 'reserved': amount, 'charged': amount,
                                  'measurement_valid': False, 'recovered_indeterminate': True,
                                  'runtime_phase': interrupted.phase if interrupted else None,
                                  'task_spec_id': interrupted.id if interrupted else None})
        self.expires_at, self.total_seconds = payload['expires_at'], payload['total_seconds']
        remaining = min(payload['budget']['remaining_seconds'], max(0, self.expires_at - time.time()),
                        budget.remaining_seconds())
        budget.deadline = budget.clock() + remaining
        for spec in specs:
            if self.task_states.get(spec.id) == 'running':
                for state_obj in self.discovery_states.values():
                    if state_obj.task_spec_id == spec.id:
                        state_obj.mark_interrupted_dispatched_indeterminate()
                self.task_states[spec.id] = 'inconclusive'
                self.summaries.pop(spec.id, None)
                if spec.id in self.leaf_outcomes_by_task:
                    cands = self.candidates_by_task.get(spec.id, {})
                    updated_leaves = []
                    for leaf in self.leaf_outcomes_by_task[spec.id]:
                        cand = cands.get(leaf.get('candidate_id', ''), {})
                        if leaf.get('status') == 'pending' and (
                            leaf.get('execution_state') == 'dispatched'
                            or (cand.get('dispatch_started') and not cand.get('executed'))
                        ):
                            leaf = {
                                **leaf,
                                'execution_state': 'interrupted',
                                'status': 'indeterminate',
                                'evidence_accepted': False,
                                'validation_state': 'NOT TESTED',
                                'reason_code': 'indeterminate_dispatch_not_replayed',
                            }
                        updated_leaves.append(leaf)
                    self.leaf_outcomes_by_task[spec.id] = updated_leaves
                if spec.id in self.pair_progress_by_task:
                    by_cand: dict[tuple[str, ...], list[dict[str, Any]]] = {}
                    for leaf in self.leaf_outcomes_by_task.get(spec.id, []):
                        by_cand.setdefault(tuple(leaf.get('pair_identities') or ()), []).append(leaf)
                    rebuilt_pairs = []
                    for pair_row in self.pair_progress_by_task[spec.id].get('pairs', []):
                        ident_key = tuple(pair_row.get('identities') or ())
                        leaves = by_cand.get(ident_key, pair_row.get('leaves', []))
                        rebuilt_pairs.append(pair_progress_entry(
                            pair_row.get('identities', []),
                            leaves,
                            complete=bool(pair_row.get('complete')),
                            categories=pair_row.get('categories', []),
                            reason_code=pair_row.get('reason_code', ''),
                        ))
                    self.pair_progress_by_task[spec.id] = pair_progress_summary(rebuilt_pairs)
                self.loop_event(spec, 'INCONCLUSIVE_indeterminate_dispatch_not_replayed')
            elif spec.id in self.summaries and not summary_feedback(self.summaries[spec.id], spec)['valid']:
                raise ValueError('invalid checkpoint summary')

    def refresh_observed_specs(self):
        if not self.observed_db:
            return
        import brain
        import hypothesis_ledger
        known = {spec.id for spec in self.broker.tasks.specs}
        for target in dict.fromkeys(row['target'] for row in self.base_specs):
            allowed = set().union(*(set(row['tools']) for row in self.base_specs if row['target'] == target))
            rows = {row['fingerprint']: row for row in hypothesis_ledger.observation_queue(
                self.observed_db, target, self.observation_context)}
            for planned in brain.observed_specs(self.observed_db, target, self.broker.workdir / 'operations',
                                                 self.observation_context):
                if planned.id in known:
                    continue
                if planned.target != target:
                    raise ValueError('observed TaskSpec target changed')
                # P5 generates plans, not authorization. Keep only tools already
                # admitted for this exact target and present in the Python catalog.
                tools = [tool for tool in planned.tools if tool in allowed and tool == 'hunter_run_web_loop']
                if not tools:
                    continue
                planned.tools, planned.tool_profile = tools, 'broker'
                planned.max_calls = min(planned.max_calls, PHASE_CALL_LIMITS[planned.phase])
                planned.scope_ref = next(row['scope_ref'] for row in self.base_specs if row['target'] == target)
                self.broker.tasks.confine(Path(planned.evidence_dir))
                if validate_chain([*self.broker.tasks.specs, planned]):
                    raise ValueError('observed TaskSpec admission failed')
                self.broker.tasks.specs.append(planned)
                known.add(planned.id)
                row = rows[planned.references['hypothesis_ref']]
                identity = planned.references['dimension'].get('identity')
                binding = self.broker.tasks.bindings.get(identity, {})
                if row['status'] == 'blocked' or (identity not in ('', 'anon') and binding.get('target') != target):
                    self.task_states[planned.id] = 'blocked'
                elif row['status'] in {'confirmed', 'tested_no_violation', 'not_applicable'}:
                    # Terminal P5 state is evidence, not permission to rerun.
                    self.task_states[planned.id] = 'not_tested'

    def select_task(self):
        # Finish ready observation work before report closure, preserving P5
        # priority order within the admitted registry.
        for spec in sorted(self.broker.tasks.specs, key=lambda spec: spec.phase == 'report'):
            if spec.id in self.task_states:
                continue
            if all(self.task_states.get(dep) == 'completed' for dep in spec.depends_on):
                return spec
        return None

    def member_batches(self, spec):
        """Prioritize every eligible pair; dispatch remains bounded by host gates."""
        members = {item["identity"]: {key: value for key, value in
                   self.broker.tasks.bindings[item["identity"]].items()
                   if key in {"target", "role", "test_data_only", "owned_objects_private"}}
                   for item in self.broker.session_checks(spec)
                   if self.broker.tasks.bindings[item["identity"]].get("role") == "member"
                   and self.broker.tasks.bindings[item["identity"]].get("test_data_only") is True
                   and self.broker.tasks.bindings[item["identity"]].get("owned_objects_private") is True}
        names = list(members)
        if len(names) > 8:
            raise WorkflowError("host_member_identity_limit")
        if len(names) < 2:
            return []
        pending = list(combinations(names, 2))
        priorities = {"cross_tenant_user": 0, "same_tenant_other_user": 1, "different_role": 2}
        pairs = []
        covered: set[str] = set()
        while pending:
            # Within a category, cover new identities before repeating one.
            pair = min(pending, key=lambda pair: (
                min((priorities[category] for category in self.member_pair_categories(pair)), default=3),
                -len(set(pair) - covered), pair))
            pending.remove(pair)
            pairs.append(pair)
            covered.update(pair)
        return [{name: members[name] for name in pair} for pair in pairs]

    @property
    def access_batches(self):
        """Compatibility view of the active task, not first-access initialization."""
        spec = self.broker.tasks.active_spec
        return self.batches_by_task.get(spec.id, []) if spec else []

    @access_batches.setter
    def access_batches(self, value):
        self.batches_by_task[self.broker.tasks.active_spec.id] = value

    def add_gap(self, spec, reason, category="prerequisites", row=None, provenance=None):
        if row is not None and row.get("slice_candidate_ids") and spec.id in self.candidates_by_task:
            row.update(validation_state="NOT TESTED", reason_code=reason)
            for ident in row["slice_candidate_ids"]:
                leaf = self.candidates_by_task[spec.id].get(ident)
                if leaf is not None:
                    self.add_gap(spec, reason, category, leaf, provenance=provenance)
            return
        item = gap(reason, category=category, task=spec.id,
                   candidate=row["candidate_id"] if row else "", provenance=provenance or (row or {}).get("provenance"))
        self.coverage_gaps[spec.id] = dedup_gaps([*self.coverage_gaps.get(spec.id, []), item])
        if row is not None:
            row.update(validation_state="NOT TESTED", reason_code=reason)

    def discovery(self, spec):
        """Reparse hash-bound host results from declared discovery ancestors only."""
        records, gaps = [], []
        registry = {item.id: item for item in self.broker.tasks.specs}
        for ident in upstream_ids(spec, self.broker.tasks.specs):
            source = registry[ident]
            if source.phase not in {"recon", "enum"} or ident not in self.summaries:
                continue
            for row in self.broker.results:
                if row["spec_id"] != ident or row["tool"] not in {
                        CRAWL_TOOL, "kali-tools_curl_request", "kali-tools_compose_js_routes",
                        "browser_browser_extract_links", "browser_browser_capture_requests",
                        "browser_browser_runtime_observe"}:
                    continue
                try:
                    value = self.broker.read_reference(row["content_ref"])
                except ValueError:
                    raise WorkflowError("prior_phase_evidence_changed") from None
                if not isinstance(value, dict) or value.get("error") or value.get("execution_failed"):
                    continue
                parsed = self.surface_records(value, row["arguments"], spec, row["content_ref"])
                for record in parsed:
                    record["source_spec_id"] = ident
                records.extend(parsed)
                gaps.extend(parser_gaps(value, spec.id, row["content_ref"]))
        return {"records": [json.loads(raw) for raw in dict.fromkeys(provider_json(row).decode() for row in records)],
                "coverage_gaps": dedup_gaps(gaps)}

    def task_discovery_states(self, spec):
        """Return host-private DiscoveryState instances keyed for this task."""
        return {
            key: state
            for key, state in self.discovery_states.items()
            if state.task_spec_id == spec.id and state.target == spec.target
        }

    def _discovery_state_for(self, spec, identity_ref="anon"):
        identity = normalize_identity(identity_ref)
        key = discovery_state_key(spec.id, spec.target, identity)
        state = self.discovery_states.get(key)
        if state is None:
            state = DiscoveryState(task_spec_id=spec.id, target=spec.target, identity_ref=identity)
            self.discovery_states[key] = state
        return state

    def _ingest_discovery_receipt(self, spec, row, *, source_spec_id, is_ancestor):
        ref = row["content_ref"]
        try:
            value = self.broker.read_reference(ref)
        except (ValueError, OSError, TypeError):
            raise WorkflowError("prior_phase_evidence_changed") from None
        if not isinstance(value, dict):
            return
        args = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
        provenance = {
            "source_spec_id": source_spec_id,
            "source_artifact": ref["path"],
            "source_sha256": ref["sha256"],
            "tool": row["tool"],
        }
        base_identity = normalize_identity(args.get("identity"))
        origin = urlsplit(spec.target)
        parent_url = args.get("url") or args.get("target")
        parent_action_id = None
        if isinstance(parent_url, str) and parent_url:
            parsed_parent = urlsplit(parent_url)
            if (parsed_parent.scheme, parsed_parent.netloc) == (origin.scheme, origin.netloc) and parsed_parent.username is None:
                if value.get("execution_failed"):
                    exec_status, exec_reason, http_status = "indeterminate", "execution_failed", None
                elif value.get("error"):
                    exec_status = "blocked"
                    exec_reason = str(value.get("reason_code") or "tool_error")[:96]
                    http_status = None
                else:
                    raw_status = value.get("status_code", value.get("status"))
                    http_status = raw_status if type(raw_status) is int and 100 <= raw_status <= 599 else None
                    if http_status in {401, 403}:
                        exec_status, exec_reason = "blocked", f"http_{http_status}"
                    elif row["tool"] == CRAWL_TOOL and value.get("ok") is False:
                        exec_status = "blocked"
                        exec_reason = str(value.get("reason_code") or "crawl_failed")[:96]
                    elif http_status is not None or row["tool"] == CRAWL_TOOL:
                        exec_status, exec_reason = "completed", ""
                    else:
                        exec_status, exec_reason = "indeterminate", "unrecognized_tool_response"
                parent_state = self._discovery_state_for(spec, base_identity)
                parent_method = str(value.get("request_method") or args.get("method") or "GET").upper()
                parent_kind = "crawl" if row["tool"] == CRAWL_TOOL else "http_request"
                relation = "entry" if is_ancestor and source_spec_id.startswith("recon") else "observed"
                parent_action = parent_state.record_action(
                    url=parent_url,
                    method=parent_method,
                    kind=parent_kind,
                    link_relation=relation,
                    provenance=provenance,
                    status=exec_status,
                    reason_code=exec_reason,
                    http_status=http_status,
                    result_artifact=ref["path"],
                    result_sha256=ref["sha256"],
                )
                parent_action_id = parent_action["action_id"]
        if value.get("error") or value.get("execution_failed"):
            return
        crawled_statuses = {}
        surface = value.get("surface", value)
        if row["tool"] == CRAWL_TOOL and isinstance(surface, dict):
            base = parent_url or spec.target
            for key in ("records", "pages"):
                items = surface.get(key)
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_url = item.get("url") or item.get("href")
                    st = item.get("status_code", item.get("status"))
                    item_ctype = str(item.get("content_type") or "").split(";", 1)[0].strip().lower()
                    if item_ctype == "application/json":
                        continue
                    if isinstance(item_url, str) and type(st) is int and 100 <= st <= 599:
                        resolved = urljoin(base, item_url)
                        m = str(item.get("method") or "GET").upper()
                        crawled_statuses[(m, resolved)] = (
                            "blocked" if st in {401, 403} else "completed",
                            st,
                            f"http_{st}" if st in {401, 403} else "",
                        )
            if crawled_statuses:
                anon_state = self._discovery_state_for(spec, "anon")
                for action in list(anon_state.actions.values()):
                    if action.get("status") != "pending" or action.get("link_relation") == "json_link":
                        continue
                    match = crawled_statuses.get((action.get("method"), action.get("url")))
                    if match is not None and match[0] == "completed":
                        anon_state.mark_completed(
                            action["action_id"],
                            http_status=match[1],
                            result_artifact=ref["path"],
                            result_sha256=ref["sha256"],
                        )
        crawled_json_urls: set[str] = set()
        for record in self.surface_records(value, args, spec, ref):
            rec_identity = normalize_identity(record.get("identity_ref", base_identity))
            rec_state = self._discovery_state_for(spec, rec_identity)
            rec_method = str(record.get("method") or "GET").upper()
            rec_url = record["url"]
            rec_reason = str(record.get("candidate_reason") or "")
            rec_ctype = str(record.get("content_type") or "").split(";", 1)[0].strip().lower()
            if row["tool"] == CRAWL_TOOL and rec_method == "GET" and rec_ctype == "application/json":
                crawled_json_urls.add(rec_url)
                anon_state = self._discovery_state_for(spec, "anon")
                existing_anon = next(
                    (a for a in anon_state.actions.values() if a["method"] == "GET" and a["url"] == rec_url),
                    None,
                )
                if existing_anon is None or existing_anon.get("status") != "completed":
                    anon_state.record_action(
                        url=rec_url,
                        method="GET",
                        kind="http_request",
                        params=record.get("params", []),
                        link_relation="json_link",
                        parent_action_id=parent_action_id,
                        provenance=provenance,
                        status="pending",
                        carrier="json",
                        content_type=rec_ctype,
                    )
                continue
            if row["tool"] == CRAWL_TOOL and rec_method == "GET" and not rec_ctype and rec_url in crawled_json_urls:
                continue
            rec_params = record.get("params") if isinstance(record.get("params"), list) else []
            rec_carrier = (
                "json" if rec_ctype == "application/json" or any(isinstance(p, dict) and p.get("in") == "json" for p in rec_params)
                else ("form" if rec_method in {"POST", "PUT", "PATCH"} and (rec_ctype == "application/x-www-form-urlencoded" or any(isinstance(p, dict) and p.get("in") in {"body", "form"} for p in rec_params)) else "")
            )
            rec_http_status = None
            post_authorized = (
                rec_method == "POST"
                and callable(getattr(self.broker, "is_readonly_post_authorized", None))
                and self.broker.is_readonly_post_authorized(
                    rec_url,
                    carrier=rec_carrier,
                    operation_id=str(record.get("operation_id") or ""),
                )
            )
            biz_authorized = (
                rec_method in {"POST", "PUT", "PATCH"}
                and callable(getattr(self.broker, "is_business_logic_authorized", None))
                and self.broker.is_business_logic_authorized(
                    rec_url,
                    method=rec_method,
                    carrier=rec_carrier,
                    operation_id=str(record.get("operation_id") or ""),
                )
            )
            if rec_reason:
                rec_status = "blocked"
            elif "{" in rec_url or "}" in rec_url:
                rec_status, rec_reason = "blocked", "requires_request_context"
            elif rec_method not in {"GET", "HEAD"} and not (post_authorized or biz_authorized):
                rec_status, rec_reason = "blocked", "unsupported_readonly_method"
            elif post_authorized or biz_authorized:
                rec_status, rec_reason = "completed", ""
            elif (rec_method, rec_url) in crawled_statuses:
                rec_status, rec_http_status, rec_reason = crawled_statuses[(rec_method, rec_url)]
            else:
                rec_status = "pending"
            link_relation = (
                record.get("link_relation")
                or (
                    "crawl_link"
                    if row["tool"] == CRAWL_TOOL
                    else ("form_action" if rec_method != "GET" else "discovered_link")
                )
            )
            child_action = rec_state.record_action(
                url=rec_url,
                method=rec_method,
                kind="form" if rec_method != "GET" else "http_request",
                params=record.get("params", []),
                link_relation=link_relation,
                parent_action_id=parent_action_id,
                provenance=provenance,
                status=rec_status,
                reason_code=rec_reason,
                http_status=rec_http_status,
                carrier=rec_carrier,
                content_type=rec_ctype,
            )
            if self._last_surface_truncated.get(ref["path"]):
                rec_state.continuation["slice_truncated"] = True
            if parent_action_id and rec_identity != base_identity:
                parent_state = self._discovery_state_for(spec, base_identity)
                if parent_action_id in parent_state.actions:
                    children = parent_state.actions[parent_action_id].setdefault("child_action_ids", [])
                    if child_action["action_id"] not in children:
                        children.append(child_action["action_id"])
        if self._last_surface_truncated.get(ref["path"]):
            self._discovery_state_for(spec, base_identity).continuation["slice_truncated"] = True

    def hydrate_discovery_state(self, spec):
        """Hydrate private DiscoveryState from admitted ancestors and current receipts."""
        if spec.references or spec.compiled_workflows or spec.phase not in {"recon", "enum", "access"}:
            return {}
        for state_obj in self.task_discovery_states(spec).values():
            for src in state_obj.sources:
                ref = self.broker.references.get(src["source_artifact"])
                if ref is None or ref["sha256"] != src["source_sha256"]:
                    raise WorkflowError("prior_phase_evidence_changed")
                try:
                    self.broker.read_reference(ref)
                except (ValueError, OSError, TypeError):
                    raise WorkflowError("prior_phase_evidence_changed") from None
        registry = {item.id: item for item in self.broker.tasks.specs}
        for ident in upstream_ids(spec, self.broker.tasks.specs):
            source = registry[ident]
            if source.phase not in {"recon", "enum"} or ident not in self.summaries:
                continue
            previous = self.summaries[ident]
            if (
                not isinstance(previous, dict)
                or previous.get("status") not in {"done", "partial"}
                or (previous.get("target") is not None and previous.get("target") != spec.target)
            ):
                raise WorkflowError("prior_phase_summary_invalid")
            for row in self.broker.results:
                if row["spec_id"] == ident and row["tool"] in DISCOVERY_TOOLS:
                    self._ingest_discovery_receipt(spec, row, source_spec_id=ident, is_ancestor=True)
        for row in self.broker.results:
            if row["spec_id"] == spec.id and row["tool"] in DISCOVERY_TOOLS:
                self._ingest_discovery_receipt(spec, row, source_spec_id=spec.id, is_ancestor=False)
        return self.task_discovery_states(spec)

    def discovery_frontier(self, spec):
        """Return compact redacted discovery frontier from verified private state."""
        states = self.hydrate_discovery_state(spec)
        if not states or not any(state.actions for state in states.values()):
            return None
        return project_discovery_frontier(states, task_spec_id=spec.id, target=spec.target)

    def _entry_discovery_provenance(self, spec):
        """Return verified upstream entry-response provenance without fabricating object provenance."""
        registry = {item.id: item for item in self.broker.tasks.specs}
        provenance = []
        for ident in upstream_ids(spec, self.broker.tasks.specs):
            source = registry[ident]
            if source.phase not in {"recon", "enum"} or ident not in self.summaries:
                continue
            for row in self.broker.results:
                if row["spec_id"] != ident or row["tool"] not in DISCOVERY_TOOLS:
                    continue
                ref = row["content_ref"]
                try:
                    value = self.broker.read_reference(ref)
                except (ValueError, OSError, TypeError):
                    raise WorkflowError("prior_phase_evidence_changed") from None
                if not isinstance(value, dict) or value.get("error") or value.get("execution_failed"):
                    continue
                provenance.append({
                    "source_spec_id": ident,
                    "source_artifact": ref["path"],
                    "source_sha256": ref["sha256"],
                })
        return [json.loads(raw) for raw in dict.fromkeys(provider_json(row).decode() for row in provenance)]

    def plan_candidates(self, spec):
        if spec.phase != "access" or spec.references or spec.compiled_workflows:
            return []
        discovered = self.discovery(spec)
        records = discovered["records"]
        self.coverage_gaps[spec.id] = dedup_gaps([*self.coverage_gaps.get(spec.id, []), *discovered["coverage_gaps"]])
        bindings = {item["identity"]: {key: value for key, value in
            self.broker.tasks.bindings[item["identity"]].items()
            if key in {"target", "role", "test_data_only", "owned_objects_private"}}
            for item in sorted(self.broker.session_checks(spec), key=lambda item:
                self.broker.tasks.bindings[item["identity"]].get("role") != "member")}
        planned = parameter_candidates(
            spec,
            records,
            bindings,
            profile_eligibility=getattr(self.broker, "profile_eligibility", None),
        )
        provenance = [{key: record[key] for key in ("source_spec_id", "source_artifact", "source_sha256")}
                      for record in records]
        provenance = [json.loads(raw) for raw in dict.fromkeys(provider_json(row).decode() for row in provenance)]
        entry_provenance = provenance if provenance else self._entry_discovery_provenance(spec)
        idor_batches = self.batches_by_task.get(spec.id, [])
        if idor_batches and spec.vector in ("", "access", "access-idor", "authz-idor"):
            for batch in idor_batches:
                batch_valid = all(
                    ident in bindings
                    and bindings[ident].get("target") == spec.target
                    and bindings[ident].get("test_data_only") is True
                    and bindings[ident].get("owned_objects_private") is True
                    for ident in batch
                )
                args = {"target": spec.target, "live": True, "crawl": False,
                        "blind_discovery": True, "blind_max_requests": 24, "max_validations": 16,
                        "fuzz_limit": 0, "candidate_sample_limit": 0, "sleep_s": 0.2,
                        "session_bindings": provider_json(batch).decode()}
                reason = (
                    "missing_synthetic_owned_session_prerequisite"
                    if not batch_valid
                    else ("validator_not_declared" if "hunter_run_web_loop" not in spec.tools else "")
                )
                row = candidate(spec.id, route=spec.target, identity=list(batch), vector="access-idor",
                    tool="hunter_run_web_loop", arguments=args, provenance=entry_provenance,
                    reason=reason)
                if not records:
                    row["entry_discovery"] = True
                planned.append(row)
        has_eligible_entry_discovery = any(
            row["vector"] == "access-idor" and row["eligible"] for row in planned
        )
        if not records and not has_eligible_entry_discovery:
            self.add_gap(spec, "missing_declared_upstream_observations", provenance=entry_provenance)
        elif not planned:
            self.add_gap(spec, "missing_parameter_or_synthetic_identity_pair", provenance=provenance or entry_provenance)
        if not idor_batches or spec.vector not in ("", "access", "access-idor", "authz-idor"):
            for record in records:
                if record.get("method", "GET") == "GET" and not record.get("params"):
                    self.add_gap(spec, "missing_parameter_or_synthetic_identity_pair", provenance=[{
                        key: record[key] for key in ("source_spec_id", "source_artifact", "source_sha256")}])
        # Keep the existing synthetic identity-pair validation ahead of generic
        # parameters; additional capabilities must not starve the P0 reserve.
        planned.sort(key=lambda row: row["vector"] != "access-idor")
        state = self.candidates_by_task.setdefault(spec.id, {})
        for row in planned:
            if row["candidate_id"] not in state:
                state[row["candidate_id"]] = row
            else:
                current = state[row["candidate_id"]]
                current["provenance"] = [json.loads(raw) for raw in dict.fromkeys(
                    provider_json(item).decode() for item in [*current["provenance"], *row["provenance"]])]
                if not row["eligible"]:
                    # A later contradictory declaration must not leave the
                    # earlier same-key candidate eligible for host dispatch.
                    current["eligible"] = False
            if row["reason_code"] and row["reason_code"] not in {
                "profile_not_applicable_to_surface",
                "traversal_policy_not_declared",
                "traversal_policy_invalid",
                "xss_execution_disabled",
                "xss_policy_invalid",
                "redirect_policy_invalid",
                "redirect_policy_disabled",
            }:
                self.add_gap(spec, row["reason_code"], row=state[row["candidate_id"]])
        self.refresh_candidate_evidence(spec)
        return list(state.values())

    _LEAF_OUTCOME_GAP_REASONS = frozenset({
        "partial_leaf_coverage",
        "remaining_leaves_not_validated",
        "remaining_leaf_not_validated",
        "indeterminate_leaf_outcome",
        "invalid_or_missing_signed_evidence",
    })

    def _clear_candidate_leaf_gaps(self, spec, candidate_id):
        self.coverage_gaps[spec.id] = [
            item for item in self.coverage_gaps.get(spec.id, [])
            if not (item.get("candidate_id") == candidate_id
                    and item.get("reason_code") in self._LEAF_OUTCOME_GAP_REASONS)
        ]

    def _validator_core(self):
        from brain import runtime_root
        validator_path = str(runtime_root() / "mcp-servers/mcp-validator")
        if validator_path not in sys.path:
            sys.path.append(validator_path)
        import cco_validator_core
        return cco_validator_core

    def _param_leaf_inconclusive_state(self, spec, row, allowed_tools):
        """Return ('indeterminate', validation_id) only for genuine current INCONCLUSIVE evidence."""
        validator_core = self._validator_core()
        profile_key = row.get("validation_profile") or next(
            (k for k, v in PROFILES.items() if v[0] == row["vector"]), ""
        )
        allowed_oracles = profile_oracles(profile_key, "INCONCLUSIVE")
        found_invalid = False
        found_indeterminate = None
        row_method = str(row.get("method", "GET") or "GET").upper()
        row_carrier = str(row.get("carrier") or ("query" if row["param"] else "")).lower()
        for res_row in self.broker.results:
            if res_row["spec_id"] != spec.id or res_row["tool"] not in allowed_tools:
                continue
            expected = recipe_arguments(row, res_row["tool"])
            if expected is None:
                continue
            args = res_row.get("arguments", {})
            if res_row["tool"] == "hunter_run_web_loop":
                def equal_binding(a, b):
                    return json.loads(a or "{}") == json.loads(b or "{}")
                if (args.get("validation_profile") != expected.get("validation_profile")
                        or not equal_binding(args.get("session_bindings"), expected.get("session_bindings"))):
                    continue
                try:
                    report = self.broker.read_reference(res_row["content_ref"])
                except (ValueError, OSError, TypeError):
                    found_invalid = True
                    continue
                if hasattr(self.broker, "private_discovery_report") and getattr(self.broker, "private_discovery_sources", None):
                    try:
                        report = self.broker.private_discovery_report(spec, res_row["content_ref"])
                    except ValueError:
                        found_invalid = True
                        continue
                if not isinstance(report, dict) or report.get("error") or report.get("execution_failed"):
                    continue
                matching = [
                    item for item in report.get("validations", [])
                    if (isinstance(item, dict) and item.get("url") == row["route"]
                        and item.get("param") == row["param"] and item.get("method", "GET") == row_method
                        and item.get("carrier", "query") == row_carrier)
                ]
                for item in matching:
                    vid = str(item.get("validation_id") or "")
                    if item.get("verdict") != "INCONCLUSIVE":
                        found_invalid = True
                        continue
                    if vid:
                        record = validator_core.load_validation(vid)
                        if (not record or not validator_core.artifact_is_current(record, expected_target=spec.target)
                                or record.get("verdict") != "INCONCLUSIVE"
                                or record.get("target") != row["route"]):
                            found_invalid = True
                            continue
                    found_indeterminate = vid
            else:
                fields: tuple[str, ...] = ("target_url", "param", "method", "carrier")
                if res_row["tool"] == "validator_validate_business_logic":
                    fields = ("target_url", "param", "method", "carrier", "kind")
                elif row_method != "GET":
                    fields = ("target_url", "param", "method", "carrier", "body_template")
                if any(args.get(k, {"method": "GET", "carrier": "query"}.get(k))
                       != expected.get(k, {"method": "GET", "carrier": "query"}.get(k)) for k in fields):
                    continue
                try:
                    val = self.broker.read_reference(res_row["content_ref"])
                except (ValueError, OSError, TypeError):
                    found_invalid = True
                    continue
                if not isinstance(val, dict) or val.get("error") or val.get("execution_failed"):
                    continue
                vid = str(val.get("validation_id") or "")
                if not vid:
                    found_invalid = True
                    continue
                record = validator_core.load_validation(vid)
                ctx = record.get("execution_context", {}) if isinstance(record, dict) else {}
                if (not record or not validator_core.artifact_is_current(record, expected_target=spec.target)
                        or record.get("verdict") != "INCONCLUSIVE"
                        or record.get("target") != row["route"]
                        or (allowed_oracles and record.get("oracle") not in allowed_oracles)
                        or (ctx and (ctx.get("param", row["param"]) != row["param"]
                                    or ctx.get("method", "GET") != row_method
                                    or ctx.get("carrier", "query") != row_carrier))):
                    found_invalid = True
                    continue
                found_indeterminate = vid
        if found_invalid:
            return "invalid_evidence", ""
        if found_indeterminate is not None:
            return "indeterminate", found_indeterminate
        return "invalid_evidence", ""

    def refresh_candidate_evidence(self, spec):
        # Never leave a cached TESTED claim visible if reference verification
        # itself fails. Dispatch history remains; current acceptance is revoked.
        for row in self.candidates_by_task.get(spec.id, {}).values():
            if row["evidence_accepted"]:
                row.update(evidence_accepted=False, evidence_refs=[], validation_state="NOT TESTED")
                row.pop("outcome", None)
                row.pop("completion_status", None)
                row.pop("accepted_verdict", None)
        self.leaf_outcomes_by_task.pop(spec.id, None)
        self.pair_progress_by_task.pop(spec.id, None)
        sources = set(upstream_ids(spec, self.broker.tasks.specs))
        checked = set()
        for row in self.candidates_by_task.get(spec.id, {}).values():
            for provenance in row["provenance"]:
                key = (provenance.get("source_artifact"), provenance.get("source_sha256"))
                if provenance.get("source_spec_id") not in sources:
                    raise WorkflowError("prior_phase_evidence_changed")
                if key not in checked:
                    ref = self.broker.references.get(key[0])
                    if ref is None or ref["sha256"] != key[1]:
                        raise WorkflowError("prior_phase_evidence_changed")
                    try:
                        self.broker.read_reference(ref)
                    except (ValueError, OSError, TypeError):
                        raise WorkflowError("prior_phase_evidence_changed") from None
                    checked.add(key)
        outcomes = self.broker.validation_attempts(spec)
        trusted_by_id = {item["record"]["validation_id"]: item for item in outcomes}
        completion_attempts = self.broker.signed_completions(spec) if hasattr(self.broker, "signed_completions") else []
        batch_analyses: dict[str, dict[str, Any]] = {}
        accepted_by_candidate: dict[str, list[dict[str, Any]]] = {}
        param_states: dict[str, tuple[str, str]] = {}
        for row in self.candidates_by_task.get(spec.id, {}).values():
            if not row["eligible"]:
                row["outcome"] = "ineligible"
                continue
            row_method = str(row.get("method", "GET") or "GET").upper()
            row_carrier = str(row.get("carrier") or ("query" if row["param"] else "")).lower()
            allowed_tools = {row["tool"], *(row.get("recipes") or {}).keys()}
            for execution in self.broker.tools:
                if (execution.get("task_spec_id") != spec.id or execution["tool"] not in allowed_tools
                        or execution.get("origin") != "solver"):
                    continue
                receipt = json.loads(Path(execution["artifact"]).read_bytes())
                args = receipt.get("arguments", {})
                expected = recipe_arguments(row, execution["tool"])
                if expected is None:
                    continue
                fields: tuple[str, ...]
                if execution["tool"] == "hunter_run_web_loop":
                    fields = ("target", "validation_profile", "blind_discovery", "session_bindings")
                elif execution["tool"] == "validator_validate_business_logic":
                    fields = ("target_url", "param", "method", "carrier", "kind")
                elif expected.get("method", "GET") != "GET":
                    fields = ("target_url", "param", "method", "carrier", "body_template")
                else:
                    fields = ("target_url", "param", "method", "carrier")
                def equal(key):
                    if key == "session_bindings":
                        return json.loads(args.get(key) or "{}") == json.loads(expected.get(key) or "{}")
                    return args.get(key, {"method": "GET", "carrier": "query", "blind_discovery": False}.get(key)) == expected.get(key, {"method": "GET", "carrier": "query", "blind_discovery": False}.get(key))
                if all(equal(key) for key in fields):
                    row.update(admitted=True, executed=True)
                elif row["param"] and execution["tool"] == "hunter_run_web_loop":
                    result = ((receipt.get("execution") or {}).get("result") or {}).get("output")
                    if isinstance(result, str):
                        try:
                            result = json.loads(result)
                        except ValueError:
                            result = None
                    if isinstance(result, dict) and str(execution["artifact"]) in getattr(self.broker, "private_discovery_sources", {}):
                        try:
                            result = self.broker.private_discovery_report_for_execution(spec, execution["artifact"], result)
                        except (ValueError, OSError, TypeError, KeyError):
                            continue
                    if isinstance(result, dict) and args.get("validation_profile") == expected.get("validation_profile") and equal("session_bindings"):
                        def leaf(item):
                            return (isinstance(item, dict) and item.get("url") == row["route"]
                                    and item.get("param") == row["param"]
                                    and item.get("method", "GET") == row_method
                                    and item.get("carrier", "query") == row_carrier)
                        if any(leaf(item) for item in result.get("validation_queue", [])):
                            # A queue can outlive an interrupted validator. Keep
                            # its intent without claiming execution or replaying.
                            row.update(admitted=True, dispatch_started=True)
                        if any(leaf(item) for item in result.get("validations", [])):
                            row.update(admitted=True, executed=True)
                        elif any(
                            isinstance(env, dict)
                            and isinstance(env.get("payload"), dict)
                            and isinstance(env["payload"].get("execution_context"), dict)
                            and env["payload"]["execution_context"].get("url") == row["route"]
                            and env["payload"]["execution_context"].get("param", "") == row["param"]
                            and env["payload"]["execution_context"].get("method", "GET") == row_method
                            and env["payload"]["execution_context"].get("carrier", "query") == row_carrier
                            for env in (
                                *(result.get("signed_completions") or []),
                                *([result["signed_completion"]] if isinstance(result.get("signed_completion"), dict) else []),
                            )
                        ):
                            row.update(admitted=True, executed=True)
            accepted = []
            matched_completions: list[dict[str, Any]] = []
            analysis = None
            if row["vector"] == "access-idor":
                batch: dict[str, Any] = next((batch for batch in self.batches_by_task.get(spec.id, [])
                              if list(batch) == row["identity_ref"]), {})
                if batch:
                    analysis = self._analyze_member_batch(
                        spec, batch, candidate_id=row["candidate_id"], trusted_by_id=trusted_by_id
                    )
                    batch_analyses[row["candidate_id"]] = analysis
                    if analysis["complete"]:
                        accepted = [item for item in outcomes if item["record"].get("execution_context", {}).get("identity") in batch
                                    and item["record"].get("execution_context", {}).get("resource_owner") in batch]
            else:
                profile_key = row.get("validation_profile") or next(
                    (k for k, v in PROFILES.items() if v[0] == row["vector"]), ""
                )
                accepted = [item for item in outcomes if item["vector"] == row["vector"]
                    and item.get("tool", row["tool"]) in allowed_tools
                    and item["record"]["target"] == row["route"]
                    and item["record"].get("oracle") in profile_oracles(profile_key, str(item["record"].get("verdict") or ""))
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("param") == row["param"]
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("method") == row_method
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("carrier") == row_carrier
                     and (isinstance(row["identity_ref"], str) and (row["identity_ref"] == "anon" and item.get("execution_context", item["record"].get("execution_context", {})).get("identity", "anon") in {"anon", "anonymous"}
                          or row["identity_ref"] != "anon" and item.get("execution_context", item["record"].get("execution_context", {})).get("identity") == row["identity_ref"])
                          or isinstance(row["identity_ref"], list) and item.get("execution_context", item["record"].get("execution_context", {})).get("identity") in row["identity_ref"])]
                has_confirmed = any(item["record"].get("verdict") == "CONFIRMED" for item in accepted)
                if not has_confirmed:
                    for comp in completion_attempts:
                        if comp["tool"] not in allowed_tools:
                            continue
                        pl = comp["payload"]
                        ctx = pl.get("execution_context") or {}
                        if (
                            pl.get("profile") == row.get("validation_profile")
                            and ctx.get("url") == row["route"]
                            and ctx.get("param", "") == row["param"]
                            and ctx.get("method", "GET") == row_method
                            and ctx.get("carrier", "query") == row_carrier
                            and (not pl.get("candidate_id") or pl.get("candidate_id") == row["candidate_id"])
                        ):
                            if row["identity_ref"] == "anon" and ctx.get("identity", "anon") not in {"anon", "anonymous"}:
                                continue
                            if row["identity_ref"] != "anon" and isinstance(row["identity_ref"], str) and ctx.get("identity") != row["identity_ref"]:
                                continue
                            matched_completions.append(comp)
            row["evidence_accepted"] = bool(accepted or matched_completions)
            if accepted:
                accepted_by_candidate[row["candidate_id"]] = accepted
                has_confirmed = any(item["record"].get("verdict") == "CONFIRMED" for item in accepted)
                row.update(
                    admitted=True, executed=True, validation_state="TESTED", reason_code="",
                    accepted_verdict="CONFIRMED" if has_confirmed else "UNCONFIRMED",
                    outcome="positive" if has_confirmed else "completed_negative",
                    completion_status="" if has_confirmed else ("negative_verified" if matched_completions else "unconfirmed"),
                    evidence_refs=[{"validation_id": item["record"]["validation_id"],
                                    "source_artifact": item["source_artifact"],
                                    "source_sha256": item["source_sha256"]} for item in accepted],
                )
                self.coverage_gaps[spec.id] = [item for item in self.coverage_gaps.get(spec.id, [])
                                               if item.get("candidate_id") != row["candidate_id"]]
            elif matched_completions:
                comp = matched_completions[-1]
                pl = comp["payload"]
                row.update(
                    admitted=True, executed=True, validation_state="TESTED", reason_code="",
                    accepted_verdict="UNCONFIRMED",
                    outcome="completed_negative",
                    completion_status="negative_verified",
                    evidence_refs=[{
                        "validation_id": f"completion:{pl['completion_id'][:16]}",
                        "completion_id": pl["completion_id"],
                        "kind": "signed_completion",
                        "version": 1,
                        "source_artifact": comp["source_artifact"],
                        "source_sha256": comp["source_sha256"],
                    }],
                )
                self.coverage_gaps[spec.id] = [item for item in self.coverage_gaps.get(spec.id, [])
                                               if item.get("candidate_id") != row["candidate_id"]]
            elif analysis is not None and (analysis["leaves"] or analysis["saw_invalid_report"]):
                row["evidence_refs"] = []
                self._clear_candidate_leaf_gaps(spec, row["candidate_id"])
                if analysis["invalid_evidence"] > 0 or analysis["saw_invalid_report"]:
                    self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
                elif analysis["partial_coverage"]:
                    self.add_gap(spec, "partial_leaf_coverage", "partial_coverage", row)
                elif analysis["indeterminate"] > 0 and analysis["pending"] == 0:
                    self.add_gap(spec, "indeterminate_leaf_outcome", "evidence", row)
                elif analysis["pending"] > 0:
                    self.add_gap(spec, "remaining_leaves_not_validated", "admission_budget", row)
                elif row["executed"]:
                    self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
            elif row["executed"]:
                row["evidence_refs"] = []
                self._clear_candidate_leaf_gaps(spec, row["candidate_id"])
                if row["param"]:
                    leaf_state, vid = self._param_leaf_inconclusive_state(spec, row, allowed_tools)
                    param_states[row["candidate_id"]] = (leaf_state, vid)
                    if leaf_state == "indeterminate":
                        self.add_gap(spec, "indeterminate_leaf_outcome", "evidence", row)
                    else:
                        self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
                else:
                    self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
        leaf_rows: list[dict[str, Any]] = []
        for row in self.candidates_by_task.get(spec.id, {}).values():
            if row["vector"] == "access-idor":
                if row["candidate_id"] in batch_analyses:
                    leaf_rows.extend(batch_analyses[row["candidate_id"]]["leaves"])
                continue
            identity = row["identity_ref"] if isinstance(row["identity_ref"], str) else ",".join(row["identity_ref"])
            leaf_carrier = str(row.get("carrier") or ("query" if row["param"] else "")).lower()
            if row["evidence_accepted"]:
                if row["candidate_id"] in accepted_by_candidate:
                    acc = accepted_by_candidate[row["candidate_id"]][0]
                    leaf_rows.append(leaf_outcome(
                        task=spec.id, candidate_id=row["candidate_id"], vector=row["vector"],
                        url=row["route"], method=row.get("method", "GET"), param=row["param"],
                        carrier=leaf_carrier, identity=identity,
                        vuln_class=row["vector"], execution_state="executed", status="accepted",
                        verdict=str(acc["record"].get("verdict") or ""),
                        validation_id=acc["record"]["validation_id"],
                        source_artifact=str(acc.get("source_artifact") or ""),
                        source_sha256=str(acc.get("source_sha256") or ""),
                    ))
                else:
                    ev_ref = (row.get("evidence_refs") or [{}])[0]
                    leaf_rows.append(leaf_outcome(
                        task=spec.id, candidate_id=row["candidate_id"], vector=row["vector"],
                        url=row["route"], method=row.get("method", "GET"), param=row["param"],
                        carrier=leaf_carrier, identity=identity,
                        vuln_class=row["vector"], execution_state="executed", status="accepted",
                        verdict="UNCONFIRMED",
                        validation_id=str(ev_ref.get("validation_id") or ""),
                        source_artifact=str(ev_ref.get("source_artifact") or ""),
                        source_sha256=str(ev_ref.get("source_sha256") or ""),
                    ))
            elif row["executed"]:
                leaf_state, vid = param_states.get(row["candidate_id"], ("invalid_evidence", ""))
                leaf_rows.append(leaf_outcome(
                    task=spec.id, candidate_id=row["candidate_id"], vector=row["vector"],
                    url=row["route"], method=row.get("method", "GET"), param=row["param"],
                    carrier=leaf_carrier, identity=identity,
                    vuln_class=row["vector"], execution_state="executed", status=leaf_state,
                    verdict="INCONCLUSIVE" if leaf_state == "indeterminate" else "",
                    validation_id=vid, reason_code=row.get("reason_code", ""),
                ))
            elif row.get("dispatch_started") and self.task_states.get(spec.id) == "inconclusive":
                leaf_rows.append(leaf_outcome(
                    task=spec.id, candidate_id=row["candidate_id"], vector=row["vector"],
                    url=row["route"], method=row.get("method", "GET"), param=row["param"],
                    carrier=leaf_carrier, identity=identity,
                    vuln_class=row["vector"], execution_state="interrupted", status="indeterminate",
                    reason_code=row.get("reason_code") or "indeterminate_dispatch_not_replayed",
                ))
            else:
                leaf_rows.append(leaf_outcome(
                    task=spec.id, candidate_id=row["candidate_id"], vector=row["vector"],
                    url=row["route"], method=row.get("method", "GET"), param=row["param"],
                    carrier=leaf_carrier, identity=identity,
                    vuln_class=row["vector"], execution_state="pending", status="pending",
                    reason_code=row.get("reason_code") or "candidate_not_executed",
                ))
        self.leaf_outcomes_by_task[spec.id] = leaf_rows
        if not spec.references and not spec.compiled_workflows:
            self.pair_progress_by_task[spec.id] = self.member_pair_progress(spec, trusted_by_id=trusted_by_id)

    def observed_session_block(self, spec, row):
        """A host-observed stale primary session blocks repeats until refreshed."""
        bindings = json.loads(row["arguments"].get("session_bindings", "{}"))
        if not bindings:
            return ""
        primary = next(iter(bindings))
        for previous in reversed(self.broker.results):
            if previous["spec_id"] != spec.id:
                continue
            if (previous["tool"] == "validator_session_vault_check"
                    and previous["arguments"].get("identity") == primary):
                check = self.broker.read_reference(previous["content_ref"])
                if isinstance(check, dict) and check.get("status") == "fresh":
                    return ""
            if previous["tool"] != "hunter_run_web_loop":
                continue
            supplied = json.loads(previous["arguments"].get("session_bindings", "{}"))
            if not isinstance(supplied, dict) or not supplied or next(iter(supplied)) != primary:
                continue
            value = self.broker.read_reference(previous["content_ref"])
            if not isinstance(value, dict) or not isinstance(value.get("skipped", []), list):
                continue
            if any(item.get("reason_code") == "session_not_recently_verified"
                   for item in value.get("skipped", []) if isinstance(item, dict)):
                return "session_not_recently_verified"
        return ""

    def admit_candidate(self, spec, row):
        if not row["eligible"]:
            return False
        session_reason = self.observed_session_block(spec, row)
        if session_reason:
            self.add_gap(spec, session_reason, "prerequisites", row)
            return False
        policy = self.broker.runtime_policy
        reason = None
        if policy.tool_allowance(spec) == 0:
            reason = "phase_tool_budget_exhausted"
        elif self.broker.budget.available("http") == 0:
            reason = "http_budget_exhausted"
        elif not self.broker.budget.remaining_seconds():
            reason = "wall_clock_budget_exhausted"
        elif self.broker.budget.available("tokens") == 0:
            reason = "token_budget_exhausted"
        if reason:
            self.add_gap(spec, reason, "admission_budget", row)
            return False
        try:
            self.broker._check_handoff(spec)
            if row["tool"] not in policy.allowed_tools(spec):
                raise ValueError("candidate tool unavailable")
            schemas = {tool["function"]["name"]: tool["function"]["parameters"] for tool in self.tool_schemas(spec)}
            self.parse_calls([{"function": {"name": row["tool"], "arguments": provider_json(row["arguments"]).decode()}}], schemas)
            decision = self.broker.engine.validate_tool_invocation(row["tool"], row["arguments"], _policy_preflight=True)
            if not decision["allowed"]:
                raise ValueError("candidate policy denied")
        except (ValueError, KeyError):
            self.add_gap(spec, "candidate_prerequisite_or_admission_denied", "prerequisites", row)
            return False
        # A preview does not attest that dispatch passed the checks again. The
        # actual host executor receipt owns admitted/executed funnel transitions.
        return True

    def member_pair_categories(self, pair):
        """P4 facts rank comparisons, not access expectations or finding verdicts."""
        actors = [self.broker.tasks.bindings[name] for name in pair]
        if same_principal(*actors) is True:
            return []
        def fact(actor, field):
            value = identity_fact(actor, field)
            # Flat operator binding metadata can guide scheduling. Conflicting
            # or unsourced fact records must not fall back to that metadata.
            if any(isinstance(item, dict) and item.get("field") == field
                   for item in actor.get("identity_facts", [])):
                return value
            value = actor.get(field)
            return value if isinstance(value, str) and value.strip() else None
        tenant, other_tenant = (fact(actor, "tenant") for actor in actors)
        role, other_role = (fact(actor, "role") for actor in actors)
        categories = []
        if tenant and other_tenant:
            categories.append("same_tenant_other_user" if tenant == other_tenant else "cross_tenant_user")
        if role and other_role and role != other_role:
            categories.append("different_role")
        return categories

    def _pair_reason_code(self, batch, analysis, shortfalls):
        if analysis["complete"]:
            return ""
        if analysis["invalid_evidence"] > 0 or analysis["saw_invalid_report"]:
            return "invalid_or_missing_signed_evidence"
        shortfall = next(
            (item["reason_code"] for item in reversed(shortfalls) if list(batch) in item.get("pending_batches", [])),
            None,
        )
        if shortfall:
            return shortfall
        if analysis["partial_coverage"]:
            return "partial_leaf_coverage"
        if analysis["indeterminate"] > 0 and analysis["pending"] == 0:
            return "indeterminate_leaf_outcome"
        if analysis["pending"] > 0:
            return "remaining_leaves_not_validated"
        return "no_complete_current_signed_pair_queue"

    def member_pair_progress(self, spec, *, trusted_by_id=None):
        """Aggregate exact leaf outcomes per identity pair without loosening completeness."""
        if trusted_by_id is None:
            trusted_by_id = {item["record"]["validation_id"]: item for item in self.broker.validation_attempts(spec)}
        shortfalls = [row["result"] for row in self.broker.results
                      if row["spec_id"] == spec.id and row["tool"] == "host_access_batch"]
        cands = self.candidates_by_task.get(spec.id, {})
        cand_by_pair = {
            tuple(row["identity_ref"]): row["candidate_id"]
            for row in cands.values()
            if row.get("vector") == "access-idor" and isinstance(row.get("identity_ref"), list)
        }
        pairs = []
        for batch in self.member_batches(spec):
            cand_id = cand_by_pair.get(tuple(batch), "")
            analysis = self._analyze_member_batch(spec, batch, candidate_id=cand_id, trusted_by_id=trusted_by_id)
            reason = self._pair_reason_code(batch, analysis, shortfalls)
            pairs.append(pair_progress_entry(
                list(batch),
                analysis["leaves"],
                complete=analysis["complete"],
                categories=self.member_pair_categories(batch),
                reason_code=reason,
            ))
        return pair_progress_summary(pairs)

    def member_comparison_coverage(self, spec):
        """A dispatched pair needs a complete, currently signed queue to count."""
        trusted_by_id = {item["record"]["validation_id"]: item for item in self.broker.validation_attempts(spec)}
        rows = []
        shortfalls = [row["result"] for row in self.broker.results
                      if row["spec_id"] == spec.id and row["tool"] == "host_access_batch"]
        for batch in self.member_batches(spec):
            analysis = self._analyze_member_batch(spec, batch, trusted_by_id=trusted_by_id)
            complete = analysis["complete"]
            reason = self._pair_reason_code(batch, analysis, shortfalls)
            rows.append({"identities": list(batch), "categories": self.member_pair_categories(batch),
                         "status": "TESTED" if complete else "NOT TESTED",
                         "reason_code": "" if complete else reason})
        dimensions = []
        for category in ("cross_tenant_user", "same_tenant_other_user", "different_role"):
            matching = [row for row in rows if category in row["categories"]]
            complete = bool(matching) and all(row["status"] == "TESTED" for row in matching)
            dimensions.append({"category": category, "status": "TESTED" if complete else "NOT TESTED",
                               "reason_code": "" if complete else "remaining_identity_pairs_not_validated"
                               if matching else "missing_evidenced_identity_comparison",
                               "tested_pairs": sum(row["status"] == "TESTED" for row in matching),
                               "total_pairs": len(matching)})
        return rows, dimensions

    def _analyze_member_batch(self, spec, bindings, *, candidate_id="", trusted_by_id=None):
        """Inspect leaf-level outcomes and strict full-queue completeness for one pair."""
        from python_identity_discovery import public_export
        validator_core = self._validator_core()
        if trusted_by_id is None:
            trusted_by_id = {item["record"]["validation_id"]: item for item in self.broker.validation_attempts(spec)}
        best_partial: dict[str, Any] | None = None
        saw_invalid_report = False
        for row in self.broker.results:
            if row["spec_id"] != spec.id or row["tool"] != "hunter_run_web_loop":
                continue
            args = row["arguments"]
            if args.get("target") != spec.target or args.get("live") is not True or args.get("blind_discovery") is not True:
                continue
            try:
                supplied = json.loads(args.get("session_bindings", "{}"))
            except (ValueError, TypeError):
                continue
            if supplied != bindings:
                continue
            try:
                report = self.broker.read_reference(row["content_ref"])
            except (ValueError, OSError, TypeError):
                saw_invalid_report = True
                continue
            sealed_report = False
            if hasattr(self.broker, "private_discovery_report"):
                try:
                    report = self.broker.private_discovery_report(spec, row["content_ref"])
                    sealed_report = True
                except ValueError:
                    if getattr(self.broker, "private_discovery_sources", None):
                        saw_invalid_report = True
                        continue
            if not isinstance(report, dict) or report.get("error") or report.get("execution_failed"):
                saw_invalid_report = True
                continue
            discovery = report.get("identity_discovery", {})
            if not isinstance(discovery, dict):
                discovery = {}
            queue = report.get("validation_queue", [])
            validations = report.get("validations", [])
            if not isinstance(queue, list):
                queue = []
            if not isinstance(validations, list):
                validations = []
            use_url_digest = not sealed_report and any(isinstance(item, dict) and "url_sha256" in item for item in queue)

            def key(item, *, include_digest=use_url_digest):
                fields = ("url", "url_sha256") if include_digest else ("url",)
                return tuple(item.get(name) for name in (*fields, "method", "vuln_class", "operation_id",
                                                         "resource_owner", "identity"))

            def match_trusted(item):
                vid = item.get("validation_id")
                attempt = trusted_by_id.get(vid)
                record = attempt["record"] if attempt is not None else None
                if record is not None:
                    ctx = record.get("execution_context", {})
                    if record["target"] == item.get("url") and key(ctx, include_digest=False) == key(item, include_digest=False):
                        return attempt
                elif not sealed_report and not getattr(self.broker, "private_discovery_sources", None):
                    attempt = next(
                        (cand for candidate_id_k, cand in trusted_by_id.items()
                         if public_export({"validation_queue": [], "validation_id": candidate_id_k})["validation_id"] == vid),
                        None,
                    )
                    record = attempt["record"] if attempt is not None else None
                if (record is not None and not sealed_report
                        and not getattr(self.broker, "private_discovery_sources", None)
                        and isinstance(item.get("url_sha256"), str)
                        and hashlib.sha256(str(record["target"]).encode()).hexdigest() == item["url_sha256"]):
                    ctx = record.get("execution_context", {})
                    if public_export({"validation_queue": [], "url": record["target"]})["url"] != item.get("url"):
                        return None
                    public_ctx = public_export({"validation_queue": [], **ctx, "url": ctx.get("url", record["target"])})
                    if key(public_ctx, include_digest=True) == key(item, include_digest=True):
                        return attempt
                return None

            def matches_inconclusive(item):
                vid = str(item.get("validation_id") or "")
                if not vid:
                    return item.get("verdict") == "INCONCLUSIVE", ""
                record = validator_core.load_validation(vid)
                if (not record or not validator_core.artifact_is_current(record, expected_target=spec.target)
                        or record.get("verdict") != "INCONCLUSIVE"):
                    return False, ""
                ctx = record.get("execution_context", {})
                if record.get("target") == item.get("url") and key(ctx, include_digest=False) == key(item, include_digest=False):
                    return True, vid
                if (not sealed_report and not getattr(self.broker, "private_discovery_sources", None)
                        and isinstance(item.get("url_sha256"), str)
                        and hashlib.sha256(str(record["target"]).encode()).hexdigest() == item["url_sha256"]):
                    if public_export({"validation_queue": [], "url": record["target"]})["url"] != item.get("url"):
                        return False, ""
                    public_ctx = public_export({"validation_queue": [], **ctx, "url": ctx.get("url", record["target"])})
                    return key(public_ctx, include_digest=True) == key(item, include_digest=True), vid
                return False, ""

            validations_by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
            for val_item in validations:
                if isinstance(val_item, dict):
                    validations_by_key.setdefault(key(val_item), []).append(val_item)

            accepted_keys: set[tuple[Any, ...]] = set()
            accepted_attempts: list[dict[str, Any]] = []
            seen_attempt_ids: set[str] = set()
            leaves: list[dict[str, Any]] = []
            for item in queue:
                if not isinstance(item, dict):
                    continue
                k = key(item)
                leaf_base = {
                    "task": spec.id,
                    "candidate_id": candidate_id,
                    "vector": "access-idor",
                    "url": str(item.get("url") or ""),
                    "method": str(item.get("method") or "GET"),
                    "identity": str(item.get("identity") or ""),
                    "resource_owner": str(item.get("resource_owner") or ""),
                    "operation_id": item.get("operation_id"),
                    "vuln_class": str(item.get("vuln_class") or "authz-idor"),
                    "pair_identities": list(bindings),
                    "url_sha256": str(item.get("url_sha256") or "") if use_url_digest else "",
                }
                val_candidates = validations_by_key.get(k, [])
                matched_attempt = None
                for val_item in val_candidates:
                    matched_attempt = match_trusted(val_item)
                    if matched_attempt is not None:
                        break
                if matched_attempt is not None:
                    accepted_keys.add(k)
                    vid = matched_attempt["record"]["validation_id"]
                    if vid not in seen_attempt_ids:
                        seen_attempt_ids.add(vid)
                        accepted_attempts.append(matched_attempt)
                    leaves.append(leaf_outcome(
                        **leaf_base,
                        execution_state="executed",
                        status="accepted",
                        verdict=str(matched_attempt["record"].get("verdict") or ""),
                        validation_id=vid,
                        source_artifact=str(matched_attempt.get("source_artifact") or ""),
                        source_sha256=str(matched_attempt.get("source_sha256") or ""),
                    ))
                elif val_candidates:
                    val_item = val_candidates[-1]
                    is_indet, vid = matches_inconclusive(val_item)
                    if is_indet:
                        leaves.append(leaf_outcome(
                            **leaf_base,
                            execution_state="executed",
                            status="indeterminate",
                            verdict="INCONCLUSIVE",
                            validation_id=vid,
                            reason_code="indeterminate_leaf_outcome",
                        ))
                    else:
                        leaves.append(leaf_outcome(
                            **leaf_base,
                            execution_state="executed",
                            status="invalid_evidence",
                            verdict=str(val_item.get("verdict") or ""),
                            validation_id=str(val_item.get("validation_id") or ""),
                            reason_code="invalid_or_missing_signed_evidence",
                        ))
                elif self.task_states.get(spec.id) == "inconclusive":
                    leaves.append(leaf_outcome(
                        **leaf_base,
                        execution_state="interrupted",
                        status="indeterminate",
                        reason_code="indeterminate_dispatch_not_replayed",
                    ))
                else:
                    leaves.append(leaf_outcome(
                        **leaf_base,
                        execution_state="pending",
                        status="pending",
                        reason_code="remaining_leaf_not_validated",
                    ))

            orphan_invalid = any(
                isinstance(val_item, dict)
                and key(val_item) not in {key(q) for q in queue if isinstance(q, dict)}
                and match_trusted(val_item) is None
                and not matches_inconclusive(val_item)[0]
                for val_item in validations
            )
            expected_bindings = set(bindings)
            if not sealed_report and not getattr(self.broker, "private_discovery_sources", None):
                expected_bindings = {public_export({"validation_queue": [], "resource_owner": name})["resource_owner"]
                                     for name in bindings}
            report_ready = (
                bool(report.get("ok"))
                and discovery.get("status") == "ready"
                and not discovery.get("reasons")
                and not discovery.get("budget_limited")
                and not report.get("errors")
                and not report.get("stopped")
            )
            report_complete = bool(
                report_ready
                and queue
                and {item.get("resource_owner") for item in queue if isinstance(item, dict)} == expected_bindings
                and all({item.get("resource_owner"), item.get("identity")} == expected_bindings
                        for item in queue if isinstance(item, dict))
                and all(key(item) in accepted_keys for item in queue if isinstance(item, dict))
            )
            accepted_count = sum(1 for leaf in leaves if leaf["status"] == "accepted")
            pending_count = sum(1 for leaf in leaves if leaf["status"] == "pending")
            indeterminate_count = sum(1 for leaf in leaves if leaf["status"] == "indeterminate")
            invalid_count = sum(1 for leaf in leaves if leaf["status"] == "invalid_evidence")
            analysis: dict[str, Any] = {
                "complete": report_complete,
                "leaves": leaves,
                "accepted": accepted_count,
                "pending": pending_count,
                "indeterminate": indeterminate_count,
                "invalid_evidence": invalid_count,
                "partial_coverage": bool(not report_complete and accepted_count > 0 and invalid_count == 0 and not orphan_invalid),
                "saw_invalid_report": saw_invalid_report or orphan_invalid,
                "accepted_attempts": accepted_attempts,
            }
            if report_complete:
                return analysis
            if best_partial is None or (len(analysis["leaves"]), analysis["accepted"]) >= (len(best_partial["leaves"]), best_partial["accepted"]):
                best_partial = analysis
        if best_partial is not None:
            best_partial["saw_invalid_report"] = best_partial["saw_invalid_report"] or saw_invalid_report
            best_partial["partial_coverage"] = bool(
                not best_partial["complete"]
                and best_partial["accepted"] > 0
                and best_partial["invalid_evidence"] == 0
                and not best_partial["saw_invalid_report"]
            )
            return best_partial
        return {
            "complete": False,
            "leaves": [],
            "accepted": 0,
            "pending": 0,
            "indeterminate": 0,
            "invalid_evidence": 0,
            "partial_coverage": False,
            "saw_invalid_report": saw_invalid_report,
            "accepted_attempts": [],
        }

    def completed_member_batch(self, spec, bindings):
        """Only a fully observed queue with current signed outcomes avoids replay."""
        return self._analyze_member_batch(spec, bindings)["complete"]

    def _engine_utc_now(self) -> datetime:
        engine = self.broker.engine
        module = sys.modules.get(type(engine).__module__)
        utc_now = getattr(module, "_utc_now", None) if module is not None else None
        if callable(utc_now):
            now = utc_now()
            if isinstance(now, datetime):
                return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    def _tool_rate_block_wait_seconds(self, tool_name: str, conn: Any, now_utc: datetime,
                                      needed_weight: int | None = None) -> float:
        """Return remaining window seconds before a blocked rate-limit key can accept weight."""
        engine = self.broker.engine
        window_seconds, max_calls = engine._rate_limit_for(tool_name)
        window_seconds = max(0, int(window_seconds))
        max_calls = max(0, int(max_calls))
        if window_seconds <= 0:
            return 0.0
        cap = engine.tool_capability(tool_name) if callable(getattr(engine, "tool_capability", None)) else {}
        default_weight = max(1, int((cap or {}).get("request_multiplier") or 1))
        if needed_weight is None:
            needed_weight = default_weight
        else:
            needed_weight = max(default_weight, min(max_calls, int(needed_weight)) if max_calls > 0 else int(needed_weight))
        cutoff = (now_utc - timedelta(seconds=window_seconds)).isoformat()
        try:
            rows = conn.execute(
                "SELECT timestamp, weight FROM rate_limit_reservations "
                "WHERE tool_name=? AND timestamp>? ORDER BY timestamp ASC, id ASC",
                (tool_name, cutoff),
            ).fetchall()
        except sqlite3.OperationalError:
            return 0.0
        used = sum(int(weight) for _, weight in rows)
        if not rows or used + needed_weight <= max_calls:
            return 0.0
        target_used = max(0, max_calls - needed_weight)
        wait_until: datetime | None = None
        for ts_text, weight in rows:
            used -= int(weight)
            parsed_ts = datetime.fromisoformat(str(ts_text))
            if parsed_ts.tzinfo is None:
                parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
            wait_until = parsed_ts + timedelta(seconds=window_seconds)
            if used <= target_used:
                break
        if wait_until is None:
            return 0.0
        return max(0.0, float((wait_until - now_utc).total_seconds()))

    def _blocking_rate_wait_seconds(self, spec: TaskSpec) -> float:
        """Wait only for the remaining window of actually blocking rate-limit keys."""
        default_tools = (
            "hunter_run_web_loop",
            "validator_validate_idor",
            "validator_validate_auth_bypass",
            "kali-tools_curl_request",
            "kali-tools_discover_web_surface",
        )
        pending_tools = getattr(self, "_pending_rate_tools", None)
        pending_entry = pending_tools.get(spec.id) if isinstance(pending_tools, dict) else None
        if isinstance(pending_entry, tuple):
            pending_tool, pending_weight = pending_entry
            check_specs: tuple[tuple[str, int | None], ...] = ((pending_tool, pending_weight),)
        elif isinstance(pending_entry, str) and pending_entry:
            check_specs = ((pending_entry, None),)
        else:
            check_specs = tuple((tool, None) for tool in default_tools)
        engine = self.broker.engine
        connect = getattr(engine, "_connect", None)
        audit_db = getattr(engine, "audit_db", None)
        if not callable(connect) and not audit_db:
            return float(max(engine._rate_limit_for(tool)[0] for tool, _ in check_specs))
        conn = connect() if callable(connect) else sqlite3.connect(str(audit_db))
        try:
            now_utc = self._engine_utc_now()
            return max(
                (self._tool_rate_block_wait_seconds(tool, conn, now_utc, weight) for tool, weight in check_specs),
                default=0.0,
            )
        finally:
            conn.close()

    def wait_access_rate_window(self, spec):
        """Let actually blocking request reservations expire without changing rate policy."""
        seconds = self._blocking_rate_wait_seconds(spec)
        start = self.broker.budget.clock()
        self.broker._require_open()
        waited_map = getattr(self, "_last_rate_wait_elapsed", None)
        if not isinstance(waited_map, dict):
            waited_map = {}
            self._last_rate_wait_elapsed = waited_map
        if seconds <= 0:
            waited_map[spec.id] = False
            view = self.broker.view({"status": "rate_window_elapsed", "window_seconds": 0, "elapsed_seconds": 0})
            self.broker.results.append({"spec_id": spec.id, "tool": "host_access_backoff", "arguments": {}, **view})
            dump(self.broker.private / "python-tool-results.json", self.broker.results)
            return True
        if self.broker.budget.remaining_seconds() <= seconds:
            return False
        deadline = start + seconds
        while self.broker.budget.clock() < deadline:
            self.broker.closed.wait(min(1, deadline - self.broker.budget.clock()))
            self.broker._require_open()
            if not self.broker.budget.remaining_seconds():
                raise BudgetError("wall clock budget exhausted")
        waited_map[spec.id] = True
        view = self.broker.view({"status": "rate_window_elapsed", "window_seconds": seconds,
                                 "elapsed_seconds": self.broker.budget.clock() - start})
        self.broker.results.append({"spec_id": spec.id, "tool": "host_access_backoff", "arguments": {}, **view})
        dump(self.broker.private / "python-tool-results.json", self.broker.results)
        return True

    def refresh_expiring_access_sessions(self, spec, row, *, rate_window_elapsed=False):
        """Recheck due bound identities, never extend or infer vault freshness."""
        # Only scheduled capabilities need freshness. Parameter candidates bind
        # their observed identity (or none for public routes), not the vault.
        if row.get("vector") not in {"access-idor", *(value[0] for value in PROFILES.values())}:
            return True
        bindings = json.loads(row["arguments"].get("session_bindings", "{}"))
        sources = {spec.id, *upstream_ids(spec, self.broker.tasks.specs)}
        due = []
        now = time.time()
        # Reserve only a still-pending request window before the unchanged
        # 300-second expiry. Host continuation already waited before this call;
        # counting that window again spends redundant checks on fresh sessions.
        # This estimate selects checks; per-request vault guards grant authority.
        window = 0 if rate_window_elapsed else self.broker.engine._rate_limit_for("hunter_run_web_loop")[0]
        for identity in bindings:
            previous = next((item for item in reversed(self.broker.results)
                if item["spec_id"] in sources and item["tool"] == SESSION_CHECK_TOOL
                and item["arguments"] == {"target": spec.target, "identity": identity}), None)
            if previous is None:
                # No check history is not evidence of freshness. Hunter still
                # enforces the vault and session guard at execution time.
                continue
            value = self.broker.read_reference(previous["content_ref"])
            if not isinstance(value, dict) or value.get("status") != "fresh":
                self.add_gap(spec, "session_not_recently_verified", row=row)
                return False
            checked = previous.get("session_check_observed_at")
            if (type(checked) not in (int, float) or not math.isfinite(checked)
                    or checked > now or now - checked >= max(0, 300 - window)):
                due.append({"target": spec.target, "identity": identity})
        if not due:
            return True
        policy = self.broker.runtime_policy
        if SESSION_CHECK_TOOL not in policy.allowed_tools(spec) or policy.tool_allowance(spec) < len(due) + 1:
            self.add_gap(spec, "session_refresh_unavailable_or_budget_exhausted", "admission_budget", row)
            return False
        for args in due:
            try:
                view = self.broker.invoke(SESSION_CHECK_TOOL, args)
            except BudgetError:
                raise
            except ValueError:
                self.add_gap(spec, "session_refresh_denied", row=row)
                return False
            value = self.broker.read_reference(view["content_ref"])
            if (not isinstance(value, dict) or value.get("status") != "fresh"
                    or value.get("error") or value.get("execution_failed")):
                self.add_gap(spec, "session_refresh_failed", row=row)
                return False
        return True

    def tool_schemas(self, spec):
        tools = []
        session_checks = self.broker.session_checks(spec)
        allowed = self.broker.runtime_policy.allowed_tools(spec)
        if COMPILED_WORKFLOW_TOOL in allowed and spec.compiled_workflows:
            tools.append({'type': 'function', 'function': {'name': COMPILED_WORKFLOW_TOOL,
                'description': 'Execute a host-bound compiled P7/P8 workflow with fresh source evidence.',
                'parameters': {'type': 'object', 'properties': {'binding_ref': {
                    'type': 'string', 'enum': sorted(spec.compiled_workflows)}},
                    'required': ['binding_ref'], 'additionalProperties': False}}})
        for group, rows in self.broker.catalog.items():
            for row in rows:
                full = group + "_" + row["name"]
                # Handoff/seal are host operations after validated summaries.
                if full in allowed and full not in {"kali-tools_ledger_prepare_handoff", "kali-tools_ledger_checkpoint"}:
                    parameters = copy.deepcopy(row.get("inputSchema", {"type": "object"}))
                    if full == SESSION_CHECK_TOOL:
                        if not session_checks:
                            continue
                        properties = parameters.setdefault("properties", {})
                        properties["target"] = {"type": "string", "enum": [spec.target]}
                        properties["identity"] = {"type": "string", "enum": [item["identity"] for item in session_checks]}
                        parameters["required"] = list(dict.fromkeys([*parameters.get("required", []), "target", "identity"]))
                    if full == CRAWL_TOOL and session_checks:
                        properties = parameters.setdefault("properties", {})
                        for name in ("cookie", "headers"):
                            properties.pop(name, None)
                        properties["session_target"] = {"type": "string", "enum": [spec.target]}
                        properties["identity"] = {"type": "string", "enum": [item["identity"] for item in session_checks]}
                    if full == COVERAGE_TOOL:
                        parameters.setdefault("properties", {})["target"] = {"type": "string", "enum": [spec.target]}
                        parameters["required"] = list(dict.fromkeys([*parameters.get("required", []), "target"]))
                    tools.append({"type": "function", "function": {
                        "name": full, "description": row.get("description", ""),
                        "parameters": parameters}})
        if READ_TOOL in allowed:
            tools.append({"type": "function", "function": {"name": READ_TOOL,
                "description": "Read content_ref.path; text is the requested page. Continue with next_offset until eof; do not reread the same range.", "parameters": {
                "type": "object", "properties": {"path": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 3000}},
                "required": ["path"], "additionalProperties": False}}})
        step_ids = [step.id for step in spec.steps
                    if not (spec.phase == "report" and step.id == REPORT_CARRYOVER_STEP)]
        ident_schema = {"type": "string", **({"enum": step_ids} if step_ids else {})}
        tools.append({"type": "function", "function": {"name": SUMMARY_TOOL, "parameters": {
            "type": "object", "properties": {"status": {"type": "string", "enum": ["done", "partial", "blocked", "failed"]},
                "next": {"type": "string"}, "steps": {"type": "array", "minItems": len(step_ids), "maxItems": len(step_ids), "items": {
                    "type": "object", "properties": {"id": ident_schema,
                        "status": {"type": "string", "enum": ["done", "blocked", "not_tested"]}},
                    "required": ["id", "status"]}}}, "required": ["status", "next", "steps"]}}})
        return compact_tools(tools, strip_annotations=True)

    def context(self, spec, feedback=None):
        rows = [row for row in self.broker.results if row["spec_id"] == spec.id]
        # Preserve every call in the host log, but repeated identical reads
        # add no information to a fresh model context or its archive index.
        seen_reads = set()
        unique = []
        for row in reversed(rows):
            if row["tool"] == READ_TOOL:
                digest = row["content_ref"]["sha256"]
                if digest in seen_reads:
                    continue
                seen_reads.add(digest)
            unique.append(row)
        rows = list(reversed(unique))
        keep = self.recent_results
        old, recent = (rows[:-keep], rows[-keep:]) if keep else (rows, [])
        recent_views = []
        for index, row in enumerate(recent):
            result = copy.deepcopy(row['result'])
            if row['tool'] == READ_TOOL and index < len(recent) - 1 and 'text' in result:
                result.pop('text')
                result['text_archived'] = True
            recent_views.append({'tool': row['tool'], 'result': result, 'content_ref': row['content_ref']})
        older_index = [{"tool": row["tool"], "content_ref": row["content_ref"]} for row in old]
        archive = self.broker.archive(older_index, "index") if older_index else None
        remaining, _, _ = self.broker.runtime_policy.allowance(spec)
        previous = self.summaries.get(spec.depends_on[-1]) if spec.depends_on else None
        # Never send an ever-growing previous inventory or archive index.
        previous_view = self.broker.view(previous, "previous-summary") if previous is not None else None
        handoff = None
        if spec.phase in {"access", "report"} and not spec.references:
            sources = upstream_ids(spec, self.broker.tasks.specs)
            receipts = [row for row in self.broker.branch_handoffs.values() if row["producer_spec_id"] in sources]
            handoff = self.broker.view(receipts, "handoff") if receipts else None
        context = {"schema": SCHEMA, "task_spec": spec.to_dict(), "previous_summary": previous_view,
                   "handoff": handoff, "registered_session_checks": self.broker.session_checks(spec),
                   "remaining_phase_tokens": remaining,
                   "remaining_phase_calls": PHASE_CALL_LIMITS[spec.phase] - self.broker.runtime_policy.calls.get(spec.id, 0),
                   "remaining_tool_calls": self.broker.runtime_policy.tool_allowance(spec),
                   "reserved_handoff_tool_calls": self.broker.runtime_policy.handoff_reserves.get(spec.id, 0),
                   "reserved_validation_tool_calls": self.broker.runtime_policy.validation_reserves.get(spec.id, 0),
                   "reserved_checkpoint_tool_calls": self.broker.runtime_policy.checkpoint_reserves.get(spec.id, 0),
                   "recent_results": recent_views,
                   "older_results": older_index[-8:], "older_index_ref": archive,
                   "summary_feedback": feedback}
        context["protocol_feedback"] = self.protocol_feedback.get(spec.id)
        if spec.references:
            context['planning_only'] = True
            context['goal'] = 'Plan only the referenced P5 hypothesis dimension with hunter_run_web_loop live=false.'
        discovery = self.discovery(spec) if spec.phase in {"enum", "access", "report"} else None
        has_discovery = bool(
            discovery
            and (
                spec.phase in {"access", "report"}
                or discovery.get("records")
                or discovery.get("coverage_gaps")
            )
        )
        context["discovery"] = self.broker.view(discovery, "discovery") if has_discovery else None
        frontier = self.discovery_frontier(spec) if spec.phase in {"recon", "enum"} else None
        if frontier is not None:
            context["discovery_frontier"] = frontier
        candidates = self.plan_candidates(spec)
        context["candidate_cards"] = compact_cards(candidates)
        context["candidate_count"] = len(candidates)
        gaps = self.coverage_gaps.get(spec.id, [])
        context["coverage_gaps"] = compact_gaps(gaps)
        context["coverage_gap_count"] = len(gaps)
        context["coverage_gap_archive_ref"] = self.broker.archive({"coverage_gaps": gaps}, "coverage-gaps") if gaps else None
        context["session_bindings"] = {item["identity"]: {key: value for key, value in
            self.broker.tasks.bindings[item["identity"]].items()
            if key in {"target", "role", "test_data_only", "owned_objects_private"}}
            for item in self.broker.session_checks(spec)}
        if candidates and not any(row["vector"] == "access-idor" for row in candidates):
            request_bindings = [json.loads(row["arguments"].get("session_bindings", "{}"))
                                for row in candidates if row["eligible"]]
            if request_bindings and all(binding == request_bindings[0] for binding in request_bindings):
                # A parameter-only turn advertises its actual request context,
                # not unrelated registered identities or credentials.
                context["session_bindings"] = request_bindings[0]
        # TaskSpec commands contain legacy helper instructions; use the phase
        # goals while keeping the immutable spec available to the host.
        context["task_spec"] = {key: value for key, value in context["task_spec"].items()
                                if key not in {"commands", "custom_commands"}}
        context["task_spec"]["steps"] = [{"id": step.id, "goal": step.command, "optional": step.optional,
                                           "host_managed": spec.phase == "report" and step.id == REPORT_CARRYOVER_STEP}
                                          for step in spec.steps]
        return context

    def inherited_http_observations(self, spec):
        observations = []
        for ident in spec.depends_on:
            previous = self.summaries.get(ident)
            if previous is None:
                continue
            source = next(item for item in self.broker.tasks.specs if item.id == ident)
            if (not summary_feedback(previous, source)["valid"]
                    or previous.get("status") not in {"done", "partial"} or previous.get("target") != spec.target):
                raise WorkflowError("prior_phase_summary_invalid")
            for row in self.broker.results:
                if row["spec_id"] != ident or row["tool"] == READ_TOOL:
                    continue
                ref = row["content_ref"]
                path = self.broker.workdir / ref["path"]
                if (self.broker.references.get(ref["path"]) != ref or path.is_symlink()
                        or self.broker.workdir not in path.resolve().parents):
                    raise WorkflowError("prior_phase_evidence_changed")
                raw = path.read_bytes()
                if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                    raise WorkflowError("prior_phase_evidence_changed")
                value = json.loads(raw)
                if not isinstance(value, dict) or value.get("error") or value.get("execution_failed"):
                    continue
                url = row["arguments"].get("url")
                status = value.get("status_code", value.get("status"))
                method = value.get("request_method", row["arguments"].get("method", "GET"))
                if (not isinstance(url, str) or type(status) is not int or not 100 <= status <= 599
                        or not isinstance(method, str) or method not in {"GET", "HEAD"}):
                    continue
                observed, target = urlsplit(url), urlsplit(spec.target)
                if (observed.scheme, observed.netloc) != (target.scheme, target.netloc):
                    continue
                observations.append({"url": url, "status": status, "artifact": ref["path"],
                    "sha256": ref["sha256"], "source_spec_id": ident, "tool": row["tool"],
                    "records": self.surface_records(value, row["arguments"], spec, ref)})
        return observations

    def surface_records(self, value, args, spec, ref):
        """Parse actual tool output; a discovered link is never a tested route."""
        from brain import runtime_root
        surface_path = str(runtime_root() / "mcp-servers/mcp-memory-server")
        if surface_path not in sys.path:
            sys.path.append(surface_path)
        from cco_surface_core.extract import (
            extract_html,
            extract_inline_scripts,
            extract_js,
            extract_js_calls,
            extract_spa_routes,
            find_spec_urls,
        )
        from cco_surface_core.parsers import parse_openapi
        base = args.get("url") or args.get("target") or spec.target
        records = []
        json_records = []
        truncated = False
        status = value.get("status_code", value.get("status"))
        if type(status) is int and 200 <= status < 300 and isinstance(value.get("text"), str):
            body_text = value["text"]
            stripped = body_text.lstrip()
            raw_headers = value.get("headers") if isinstance(value.get("headers"), dict) else {}
            resp_ctype = next(
                (str(v).split(";", 1)[0].strip().lower()
                 for k, v in raw_headers.items() if str(k).lower() == "content-type"),
                "",
            )
            base_path = urlsplit(base).path.lower()
            is_js_resp = (
                base_path.endswith((".js", ".mjs"))
                or "javascript" in resp_ctype
                or resp_ctype == "application/ecmascript"
            ) and not stripped.startswith("<")
            if stripped.startswith(("{", "[")):
                try:
                    parsed_body = json.loads(body_text)
                except ValueError:
                    parsed_body = None
                if isinstance(parsed_body, dict) and isinstance(parsed_body.get("paths"), dict) and (
                    "openapi" in parsed_body or "swagger" in parsed_body
                ):
                    records.extend(parse_openapi(
                        parsed_body,
                        target=urlsplit(spec.target).hostname or "",
                        base=spec.target,
                    ))
                elif isinstance(parsed_body, (dict, list)):
                    extracted, body_trunc = extract_json_hypermedia(parsed_body, base, origin_url=spec.target)
                    json_records.extend(extracted)
                    truncated = truncated or body_trunc
            elif is_js_resp:
                records.extend(extract_js(body_text, spec.target))
                records.extend(extract_js_calls(body_text, spec.target))
                records.extend(extract_spa_routes(body_text, spec.target))
                for spec_url in find_spec_urls(body_text, spec.target):
                    records.append({"url": spec_url, "method": "GET", "link_relation": "schema"})
            else:
                records.extend(extract_html(body_text, base))
                records.extend(extract_spa_routes(body_text, base))
                for inline_js in extract_inline_scripts(body_text):
                    records.extend(extract_js(inline_js, base))
                    records.extend(extract_js_calls(inline_js, base))
                    records.extend(extract_spa_routes(inline_js, base))
                    for spec_url in find_spec_urls(inline_js, base):
                        records.append({"url": spec_url, "method": "GET", "link_relation": "schema"})
        surface = value.get("surface", value)
        if isinstance(surface, dict):
            raw_records = surface.get("records")
            record_list = raw_records if isinstance(raw_records, list) else []
            known_record_urls = {
                urljoin(base, str(item.get("url") or item.get("href") or ""))
                for item in record_list
                if isinstance(item, dict) and (item.get("url") or item.get("href"))
            }
            for key in ("records", "work_queue", "pages", "urls_sample", "links", "internal_links", "js_files"):
                bucket = surface.get(key, [])
                for item in bucket if isinstance(bucket, list) else []:
                    if isinstance(item, str):
                        if key in {"urls_sample", "js_files"} and urljoin(base, item) in known_record_urls:
                            continue
                        records.append({"url": item, "method": "GET"})
                    elif isinstance(item, dict):
                        records.append(item)
            for hroute in surface.get("hash_routes") or []:
                if isinstance(hroute, str) and hroute.strip():
                    cleaned = hroute.strip()[1:] if hroute.strip().startswith("#/") else hroute.strip()
                    records.append({"url": cleaned, "method": "GET", "link_relation": "spa_hash"})
            if not record_list:
                for bucket_key in ("routes", "next_probes", "templates"):
                    for item in surface.get(bucket_key) or []:
                        if isinstance(item, str) and item.strip():
                            records.append({"url": item.strip(), "method": "GET"})
            extracted_surface, surf_trunc = extract_json_hypermedia(
                surface, base, origin_url=spec.target, from_http_body=False
            )
            json_records.extend(extracted_surface)
            truncated = truncated or surf_trunc
        self._last_surface_truncated[ref["path"]] = truncated
        output: list[dict[str, Any]] = []
        seen_indices: dict[bytes, int] = {}
        origin = urlsplit(spec.target)
        for record in [*records, *json_records]:
            url = record.get("url") or record.get("href")
            if not isinstance(url, str):
                continue
            url = urljoin(base, url)
            parsed = urlsplit(url)
            if (
                parsed.scheme.lower() not in {"http", "https"}
                or (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc)
                or parsed.username is not None
            ):
                continue
            url = parsed._replace(fragment="").geturl()
            method = str(record.get("method", "GET") or "GET").upper()
            derived_params, content_type = structured_params_from_node(record, method)
            if not content_type and isinstance(record.get("content_type"), str):
                content_type = record["content_type"].split(";", 1)[0].strip().lower()
            raw_params = record.get("params") if "params" in record else (derived_params if derived_params is not None else [])
            reason = str(record.get("candidate_reason") or "")
            try:
                params = parameter_declarations(raw_params)
                query = query_parameters(url)
            except ValueError as exc:
                reason, params, query = reason or str(exc), [], {}
            names = {item["name"] for item in params}
            params.extend({"name": key, "in": "query", "sample": val} for key, val in query.items() if key not in names)
            has_identity = "identity_ref" in record or "identity" in record or "identity" in args
            identity = record.get("identity_ref", record.get("identity", args.get("identity")))
            if not has_identity and "url" in args and not args.get("cookie") and not args.get("headers"):
                identity = "anon"
                has_identity = True
            operation_id = record.get("operation_id") if isinstance(record.get("operation_id"), str) and record.get("operation_id") else ""
            dedup_key = provider_json([url, method, content_type, params, reason, identity if has_identity else None])
            link_relation = record.get("link_relation")
            if dedup_key in seen_indices:
                existing = output[seen_indices[dedup_key]]
                if link_relation == "pagination" or (link_relation == "json_link" and "link_relation" not in existing):
                    existing["link_relation"] = link_relation
                if operation_id and "operation_id" not in existing:
                    existing["operation_id"] = operation_id
                continue
            seen_indices[dedup_key] = len(output)
            row = {
                "url": url,
                "method": method,
                "params": params,
                "candidate_reason": reason,
                **({"content_type": content_type} if content_type else {}),
                **({"operation_id": operation_id} if operation_id else {}),
                **({"identity_ref": identity} if has_identity else {}),
                **({"link_relation": link_relation} if isinstance(link_relation, str) and link_relation else {}),
                "source_artifact": ref["path"],
                "source_sha256": ref["sha256"],
            }
            output.append(row)
        return output

    def compile_summary(self, spec, submitted):
        if not isinstance(submitted, dict):
            return submitted
        summary = skeleton_summary(spec)
        # Only narrative and declared step states come from the model.
        for key in ("status", "next", "steps"):
            if key in submitted:
                summary[key] = submitted[key]
        routes: list[Any] = []
        params: list[Any] = []
        probes: list[dict[str, Any]] = []
        tested: list[dict[str, Any]] = []
        formats: list[dict[str, Any]] = []
        evidence, observed_records = [], []
        for row in self.broker.results:
            if row["spec_id"] != spec.id or row["tool"] == READ_TOOL:
                continue
            ref = row["content_ref"]
            value = self.broker.read_reference(ref)
            evidence.append({"kind": "host_tool_result", "tool": row["tool"], "artifact": ref["path"], "sha256": ref["sha256"]})
            if not isinstance(value, dict) or value.get("execution_failed") or value.get("error"):
                continue
            args = row["arguments"]
            observed_records.extend(self.surface_records(value, args, spec, ref))
            self.coverage_gaps[spec.id] = dedup_gaps([*self.coverage_gaps.get(spec.id, []),
                                                    *parser_gaps(value, spec.id, ref)])
            url = args.get("url")
            status = value.get("status_code", value.get("status"))
            if url and type(status) is int and 100 <= status <= 599:
                routes.append(url)
                probes.append({"url": url, "status": status, "artifact": ref["path"]})
                params.extend(name for name, _ in parse_qsl(urlsplit(url).query))
            surface = value.get("surface", value)
            if isinstance(surface, dict):
                for field, output in (("routes", routes), ("params", params)):
                    if isinstance(surface.get(field), list):
                        output.extend(surface[field])
                if isinstance(surface.get("id_formats"), list):
                    formats.extend(surface["id_formats"])
                for field in ("links", "internal_links", "urls_with_params", "form_actions", "js_files"):
                    links = surface.get(field)
                    if isinstance(links, list):
                        for link in links:
                            text = link if isinstance(link, str) else link.get("href", link.get("url", "")) if isinstance(link, dict) else ""
                            if not isinstance(text, str) or not text:
                                continue
                            observed, target = urlsplit(urljoin(spec.target, text)), urlsplit(spec.target)
                            if (observed.scheme, observed.netloc) != (target.scheme, target.netloc):
                                continue
                            routes.append(urljoin(spec.target, text))
                            params.extend(name for name, _ in parse_qsl(observed.query))
                for field in ("records", "work_queue"):
                    records = surface.get(field)
                    if isinstance(records, list):
                        for record in records:
                            if not isinstance(record, dict):
                                continue
                            if isinstance(record.get("url"), str):
                                routes.append(record["url"])
                                if type(record.get("status")) is int:
                                    probes.append({"url": record["url"], "status": record["status"], "artifact": ref["path"]})
                            if isinstance(record.get("params"), list):
                                params.extend(record["params"])
            if isinstance(args.get("param"), str):
                params.append(args["param"])
        for record in observed_records:
            routes.append(record["url"])
            params.extend(item["name"] for item in record["params"])
        summary.update(evidence=evidence, findings=self.broker.verified_findings(spec),
                       route_probes=probes, tested_parameters=tested)
        if spec.compiled_workflows:
            summary['compiled_workflows'] = self.broker.verified_workflow_executions(spec)
        if spec.phase == "enum":
            # Carry real discovery forward without claiming enum re-executed
            # it. Failed current tools cannot erase a verified dependency's
            # observation; model-authored inventory is never a fallback.
            inherited = self.inherited_http_observations(spec)
            summary["inherited_http_observations"] = inherited
            for item in inherited:
                routes.append(item["url"])
                params.extend(name for name, _ in parse_qsl(urlsplit(item["url"]).query))
                observed_records.extend(item["records"])
                for record in item["records"]:
                    routes.append(record["url"])
                    params.extend(param["name"] for param in record["params"])
                evidence.append({"kind": "prior_phase_http_observation", "tool": item["tool"],
                    "source_spec_id": item["source_spec_id"], "artifact": item["artifact"], "sha256": item["sha256"]})
            # Formats describe observed path segments, never ownership or
            # generated candidate values. Preserve placeholders as placeholders.
            for route in routes:
                raw_text = route if isinstance(route, str) else route.get("url", route.get("path", "")) if isinstance(route, dict) else ""
                text = raw_text if isinstance(raw_text, str) else ""
                parts = [part for part in urlsplit(text).path.split("/") if part]
                for index, part in enumerate(parts):
                    if re.fullmatch(r"v\d+", part, re.IGNORECASE) or not (re.search(r"\d", part) or ":id" in part):
                        continue
                    kind = "int" if part.isdecimal() else "uuid" if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", part) else "other" if ":id" in part else "string"
                    formats.append({"family": parts[index - 1] if index else "path", "format": kind, "example": part})
            # Documentation fetches retain provenance across phases. Current
            # route_probes/tested_parameters still describe enum executions.
            summary["surface"] = {"routes": list(dict.fromkeys(provider_json(x).decode() for x in routes)),
                                  "params": list(dict.fromkeys(provider_json(x).decode() for x in params)),
                                  "docs_probes": [*probes, *inherited]}
            summary["surface"]["id_formats"] = [json.loads(raw) for raw in dict.fromkeys(provider_json(item).decode() for item in formats)]
            # Preserve strings as strings (dicts keep their observed structure).
            summary["surface"]["routes"] = [json.loads(x) for x in summary["surface"]["routes"]]
            summary["surface"]["params"] = list(dict.fromkeys(
                item.get("name") if isinstance(item, dict) else item
                for item in (json.loads(x) for x in summary["surface"]["params"])
                if isinstance(item, str) or isinstance(item, dict) and isinstance(item.get("name"), str)))
            summary["surface"]["records"] = observed_records
        # A submitted finding is never authority for coverage/CONFIRMED.
        summary["hypotheses"] = submitted.get("findings", [])
        if spec.phase == "access":
            import hypothesis_ledger as hypotheses
            outcomes = self.broker.validation_attempts(spec)
            tested = [{"parameter": item.get("execution_context", item["record"].get("execution_context", {})).get("param"),
                        "validation_id": item["record"]["validation_id"], "artifact": item["source_artifact"]}
                       for item in outcomes if item.get("execution_context", item["record"].get("execution_context", {})).get("param")]
            summary["tested_parameters"] = tested
            candidates = self.plan_candidates(spec)
            updated_gap = False
            for row in candidates:
                if not row["evidence_accepted"] and not row["reason_code"]:
                    if row.get("dispatch_started") and not row["executed"] and self.task_states.get(spec.id) == "inconclusive":
                        self.add_gap(spec, "indeterminate_dispatch_not_replayed", "evidence", row)
                    else:
                        self.add_gap(spec, "invalid_or_missing_signed_evidence" if row["executed"] else "candidate_not_executed",
                                     "evidence" if row["executed"] else "admission_budget", row)
                    updated_gap = True
            if updated_gap:
                self.refresh_candidate_evidence(spec)
            summary["validation_funnel"] = funnel(candidates)
            summary["coverage_accounting"] = {
                "schema": "python-coverage-accounting/1",
                "denominators": dict(summary["validation_funnel"]["denominators"]),
                "outcomes": dict(summary["validation_funnel"]["outcomes"]),
                "confirmed_findings": len(summary["findings"]),
                "verified_negatives": sum(
                    1 for row in candidates
                    if row.get("evidence_accepted") and row.get("completion_status") == "negative_verified"
                ),
            }
            summary["leaf_outcomes"] = copy.deepcopy(self.leaf_outcomes_by_task.get(spec.id, []))
            summary["leaf_validation_funnel"] = {
                k: v for k, v in leaf_funnel(summary["leaf_outcomes"]).items() if k != "outcomes"
            }
            summary["validation_outcomes"] = [{"vector": item["vector"],
                "validation_id": item["record"]["validation_id"], "verdict": item["record"]["verdict"],
                "url": item["record"]["target"], "source_artifact": item["source_artifact"],
                "source_sha256": item["source_sha256"]} for item in outcomes]
            tested_vectors = {item["vector"] for item in outcomes}
            confirmed_vectors = {item["vector"] for item in outcomes if item["record"]["verdict"] == "CONFIRMED"}
            summary["not_tested_reasons"] = [{"vector": vector,
                "reason_code": "remaining_surface_not_validated" if vector in tested_vectors else "no_current_validator_artifact",
                "observed_attempts": sum(item["vector"] == vector for item in outcomes)}
                for vector in hypotheses.DEFAULT_VECTORS if vector not in confirmed_vectors]
            summary["member_batch_shortfalls"] = [row["result"] for row in self.broker.results
                if row["spec_id"] == spec.id and row["tool"] == "host_access_batch"]
            if not spec.references:
                summary["identity_comparisons"], summary["identity_comparison_dimensions"] = self.member_comparison_coverage(spec)
                if not spec.compiled_workflows:
                    pair_prog = copy.deepcopy(
                        self.pair_progress_by_task.get(spec.id) or self.member_pair_progress(spec)
                    )
                    for pair_row in pair_prog.get("pairs", []):
                        pair_row.pop("leaves", None)
                    summary["pair_progress"] = pair_prog
            steps = summary.get("steps")
            if isinstance(steps, list):
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    if step.get("id") == "minimal-validation":
                        step["status"] = "done" if outcomes else "not_tested"
                    if step.get("id") == "broader-coverage" and summary["not_tested_reasons"]:
                        step["status"] = "not_tested"
                if summary.get("status") == "done" and any(row.get("status") != "done" for row in steps):
                    summary["status"] = "partial"
                if (
                    summary.get("status") == "blocked"
                    and outcomes
                    and any(isinstance(row, dict) and row.get("status") == "done" for row in steps)
                ):
                    # Accepted signed outcomes mean minimal-validation completed;
                    # untested residual slices represent partial access, not a block.
                    summary["status"] = "partial"
        if spec.phase == "report":
            sources = set(upstream_ids(spec, self.broker.tasks.specs))
            summary["validation_funnels"] = {}
            summary["leaf_validation_funnels"] = {}
            summary["pair_progress_by_task"] = {}
            report_leaves: list[dict[str, Any]] = []
            for source in self.broker.tasks.specs:
                if source.id in sources and source.id in self.candidates_by_task:
                    self.refresh_candidate_evidence(source)
                    source_leaves = self.leaf_outcomes_by_task.get(source.id, [])
                    report_leaves.extend(copy.deepcopy(source_leaves))
                    summary["validation_funnels"][source.id] = funnel(list(self.candidates_by_task[source.id].values()))
                    summary["leaf_validation_funnels"][source.id] = {
                        k: v for k, v in leaf_funnel(source_leaves).items() if k != "outcomes"
                    }
                    if not source.references and not source.compiled_workflows:
                        pair_prog = copy.deepcopy(
                            self.pair_progress_by_task.get(source.id) or self.member_pair_progress(source)
                        )
                        for pair_row in pair_prog.get("pairs", []):
                            pair_row.pop("leaves", None)
                        summary["pair_progress_by_task"][source.id] = pair_prog
                elif source.id in sources and source.id in self.leaf_outcomes_by_task:
                    source_leaves = self.leaf_outcomes_by_task[source.id]
                    report_leaves.extend(copy.deepcopy(source_leaves))
                    summary["leaf_validation_funnels"][source.id] = {
                        k: v for k, v in leaf_funnel(source_leaves).items() if k != "outcomes"
                    }
                    if source.id in self.pair_progress_by_task:
                        pair_prog = copy.deepcopy(self.pair_progress_by_task[source.id])
                        for pair_row in pair_prog.get("pairs", []):
                            pair_row.pop("leaves", None)
                        summary["pair_progress_by_task"][source.id] = pair_prog
            summary["leaf_outcomes"] = report_leaves
            summary["pair_progress"] = pair_progress_summary([
                pair
                for prog in summary["pair_progress_by_task"].values()
                for pair in prog.get("pairs", [])
            ])
            reports = [row for row in self.broker.results if row["spec_id"] == spec.id and row["tool"] == COVERAGE_TOOL]
            if reports:
                row = reports[-1]
                summary["coverage_report"] = {"content_ref": row["content_ref"], "result": row["result"]}
        if (spec.phase == "report" and any(step.id == REPORT_CARRYOVER_STEP for step in spec.steps)
                and isinstance(summary.get("steps"), list)):
            # Completion of the review is distinct from unfinished probes.
            # This host-owned step can only preserve/downgrade claimed coverage.
            unfinished = [{"phase": ident, "step": step["id"], "status": step["status"]}
                           for ident, previous in self.summaries.items() if ident in sources
                          for step in previous.get("steps", []) if step["status"] in {"blocked", "not_tested"}]
            refreshed_comparisons: list[dict[str, Any]] = []
            refreshed_dimensions: list[dict[str, Any]] = []
            source_map = {source.id: source for source in self.broker.tasks.specs}
            for ident in upstream_ids(spec, self.broker.tasks.specs):
                if ident not in sources:
                    continue
                source = source_map.get(ident)
                previous = self.summaries.get(ident, {})
                if (source is not None and source.phase == "access" and not source.references
                        and not source.compiled_workflows and ident in self.candidates_by_task):
                    comp_rows, dim_rows = self.member_comparison_coverage(source)
                    prev_tested = {
                        tuple(row.get("identities", []))
                        for row in previous.get("identity_comparisons", [])
                        if row.get("status") == "TESTED"
                    }
                    for row in comp_rows:
                        if row["status"] == "NOT TESTED" and tuple(row["identities"]) in prev_tested:
                            unfinished.append({"phase": ident, "step": "pair-comparison-revalidation", "status": "not_tested"})
                    refreshed_comparisons.extend({"phase": ident, **row} for row in comp_rows if row["status"] == "NOT TESTED")
                    refreshed_dimensions.extend({"phase": ident, **row} for row in dim_rows if row["status"] == "NOT TESTED")
                elif ident in self.summaries:
                    refreshed_comparisons.extend(
                        {"phase": ident, **row} for row in previous.get("identity_comparisons", [])
                        if row["status"] == "NOT TESTED"
                    )
                    refreshed_dimensions.extend(
                        {"phase": ident, **row} for row in previous.get("identity_comparison_dimensions", [])
                        if row["status"] == "NOT TESTED"
                    )
            summary["unfinished_work"] = unfinished
            summary["identity_comparisons"] = refreshed_comparisons
            summary["identity_comparison_dimensions"] = refreshed_dimensions
            steps = summary["steps"]
            if all(isinstance(step, dict) for step in steps):
                summary["steps"] = [step for step in steps if step.get("id") != REPORT_CARRYOVER_STEP]
                summary["steps"].append({"id": REPORT_CARRYOVER_STEP, "status": "not_tested" if unfinished else "done"})
                if unfinished and summary.get("status") == "done":
                    summary["status"] = "partial"
        inherited_gaps = [row for ident in upstream_ids(spec, self.broker.tasks.specs)
                          for row in [*self.summaries.get(ident, {}).get("coverage_gaps", []),
                                      *self.coverage_gaps.get(ident, [])]]
        summary["coverage_gaps"] = dedup_gaps([*inherited_gaps, *self.coverage_gaps.get(spec.id, [])])
        return summary

    def deterministic_unaccepted_slice(self, spec, candidate):
        """One host validation may follow a measured, completed model attempt.

        Unknown dispatches/reservations and host attempts are never replayed.
        This only selects work; current prerequisites/admission still apply.
        """
        if candidate.get("dispatch_started") or candidate["evidence_accepted"]:
            return False
        allowed_tools = {candidate["tool"], *(candidate.get("recipes") or {}).keys()}
        for execution in reversed(self.broker.tools):
            if (execution.get("task_spec_id") != spec.id or execution.get("origin") != "solver"
                    or execution["tool"] not in allowed_tools):
                continue
            expected = recipe_arguments(candidate, execution["tool"])
            if expected is None:
                continue
            receipt = json.loads(Path(execution["artifact"]).read_bytes())
            result = receipt.get("execution")
            if receipt.get("arguments") != expected:
                continue
            if (receipt.get("error") or not isinstance(result, dict) or result.get("execution_failed")
                    or type(result.get("actual_request_cost")) is not int or result["actual_request_cost"] < 0):
                return False
            value = result.get("result", {}).get("output")
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except ValueError:
                    return False
            if not isinstance(value, dict):
                return False
            if (value.get("ok") is False or value.get("stopped") or value.get("errors")
                    or value.get("identity_discovery", {}).get("status") == "blocked"):
                return False
            ids = {item.get("validation_id") for item in [value, *(value.get("validations") or [])]
                   if isinstance(item, dict)}
            if any(item["record"]["validation_id"] in ids for item in self.broker.validation_attempts(spec)):
                # Partial accepted work is not a reason to blindly repeat the
                # entire slice; retain the remaining coverage gap instead.
                return False
            return any(row["spec_id"] == spec.id and row["tool"] == execution["tool"]
                       and row["arguments"] == expected
                       and self.broker.read_reference(row["content_ref"]) == value for row in self.broker.results)
        return False

    def parameter_slice(self, spec, candidates, target, profile):
        """Coalesce an observed GET index into Hunter's bounded profile slice.

        Leaf candidates retain their own provenance and signed outcomes. An
        index is a scheduling pointer, never evidence that its descendants ran.
        """
        if profile not in PROFILES or spec.references or spec.compiled_workflows:
            return None
        if "hunter_run_web_loop" not in spec.tools:
            return None
        parsed = urlsplit(target)
        records = self.discovery(spec)["records"]
        if (parsed.query or parsed.fragment or target not in {spec.target, *(
                r["url"] for r in records if r.get("method") == "GET" and not r.get("params"))}):
            return None
        def under_prefix(row):
            url = urlsplit(row["route"])
            prefix = parsed.path.rstrip("/")
            return ((url.scheme, url.netloc) == (parsed.scheme, parsed.netloc)
                    and (url.path == prefix or url.path.startswith(prefix + "/")))
        def below(row):
            if (row.get("method", "GET"), row.get("carrier", "query")) not in {("GET", "query"), ("POST", "form")}:
                return False
            return under_prefix(row)
        def hunter_args(row):
            return recipe_arguments(row, "hunter_run_web_loop")
        rows = [row for row in candidates if below(row) and (hunter_args(row) or {}).get("validation_profile") == profile]
        transports = {(row.get("method", "GET"), row.get("carrier", "query")) for row in rows}
        if len(transports) != 1:
            return None
        slice_transport = next(iter(transports))
        if slice_transport == ("POST", "form") and any(row.get("tool") != "hunter_run_web_loop" for row in rows):
            return None
        if (not rows or any(not row["eligible"] or row["executed"] and not row["evidence_accepted"]
                            or row.get("dispatch_started") and not row["evidence_accepted"] for row in rows)):
            return None
        pending = [row for row in rows if not row["evidence_accepted"]]
        if not pending or len(pending) != len(rows) or len({row["param"] for row in rows}) != 1:
            return None
        first_args = hunter_args(pending[0])
        if first_args is None:
            return None
        args = {**first_args, "target": target}
        if any({**(hunter_args(row) or {}), "target": target} != args for row in rows):
            return None
        # Reject malformed/unsupported descendants rather than allowing a broad
        # prefix to bypass a leaf's eligibility gate.
        if any(
            under_prefix(row)
            and not row["eligible"]
            and (not row.get("validation_profile") or row.get("validation_profile") == profile)
            for row in candidates
        ):
            return None
        return {**copy.deepcopy(pending[0]), "tool": "hunter_run_web_loop", "arguments": args,
                "slice_candidate_ids": [row["candidate_id"] for row in pending]}

    def parameter_continuation(self, spec, candidates, pending_params=None):
        """Coalesce pending query leaves across all supported profiles plus exact residuals."""
        if pending_params is None:
            pending_params = [
                row for row in candidates
                if row["param"] and row["eligible"] and not row["evidence_accepted"]
                and not row.get("dispatch_started")
                and (not row["executed"] or self.deterministic_unaccepted_slice(spec, row))
            ]
        if not pending_params:
            return []
        pending_ids = {row["candidate_id"] for row in pending_params}
        targets = list(dict.fromkeys([
            spec.target,
            *(record["url"] for record in self.discovery(spec)["records"]
              if isinstance(record, dict) and isinstance(record.get("url"), str)),
        ]))
        selected = []
        covered: set[str] = set()
        for profile in PROFILES:
            slices = []
            for target in targets:
                sliced = self.parameter_slice(spec, candidates, target, profile)
                if sliced and 1 < len(sliced["slice_candidate_ids"]) <= sliced["arguments"]["fuzz_limit"]:
                    slices.append(sliced)
            for sliced in sorted(slices, key=lambda row: (-len(row["arguments"]["target"]), row["arguments"]["target"])):
                ids = set(sliced["slice_candidate_ids"])
                if not ids & covered and ids <= pending_ids:
                    selected.append(sliced)
                    covered.update(ids)
        combined = [*selected, *(row for row in pending_params if row["candidate_id"] not in covered)]
        fair_selected, fair_deferred = interleave_fair_work(combined, max_queue_size=MAX_SCHEDULER_QUEUE)
        self._last_scheduler_deferred = fair_deferred
        return fair_selected

    def _is_premature_enum_summary(self, spec, submitted):
        """True when an enum summary skips required discovery or leaves frontier continuation."""
        if spec.phase != "enum" or spec.references or spec.compiled_workflows:
            return False
        if not isinstance(submitted, dict):
            return False
        enum_results = [
            row for row in self.broker.results
            if row["spec_id"] == spec.id and row["tool"] in DISCOVERY_TOOLS
        ]
        status = submitted.get("status")
        if status == "blocked":
            return not enum_results
        if status not in {"done", "partial"}:
            return False
        if not enum_results:
            return True
        states = self.hydrate_discovery_state(spec)
        pending = [action for state in states.values() for action in state.pending_actions()]
        if not pending:
            return False
        if not any(row["tool"] == CRAWL_TOOL for row in enum_results):
            return True
        if any(action.get("link_relation") in {"pagination", "json_link", "next"} for action in pending):
            return True
        if submitted.get("status") == "done" and surface_errors(self.compile_summary(spec, submitted)):
            return True
        return False

    def _crawl_tool_allowance_needed(self, spec, identity=None):
        checks = self.broker.session_checks(spec)
        if not checks:
            return 1
        members = [row for row in checks if self.broker.tasks.bindings[row["identity"]].get("role") == "member"]
        selected_identity = identity or (members or checks)[0]["identity"]
        try:
            from cco_surface_core import session_store
            if (
                session_store.get_session(spec.target, selected_identity) is not None
                and session_store.verified_session(spec.target, selected_identity) is None
            ):
                return 2
        except (ImportError, OSError, ValueError):
            return 2
        return 1

    def dispatch_discovery(self, spec, *, reason="continuation", max_actions=6):
        """Execute bounded host discovery continuation in enum while preserving handoff reserves."""
        if spec.phase != "enum" or spec.references or spec.compiled_workflows:
            return False
        states = self.hydrate_discovery_state(spec)
        max_total = 10
        total_dispatched = sum(int(state.continuation.get("dispatched_count", 0)) for state in states.values())
        if total_dispatched >= max_total:
            return False
        policy = self.broker.runtime_policy
        continued = False
        dispatched_this_call = 0
        policy.host_continuing.add(spec.id)
        try:
            def _available_tools():
                return {tool["function"]["name"]: tool["function"]["parameters"] for tool in self.tool_schemas(spec)}

            def _budget_ready(min_allowance=1):
                if policy.consecutive_failures.get(spec.id, 0) >= 2:
                    return False, "consecutive_tool_failure_limit"
                if policy.tool_allowance(spec) < min_allowance:
                    return False, "phase_tool_budget_exhausted"
                if self.broker.budget.available("http") == 0:
                    return False, "http_budget_exhausted"
                if not self.broker.budget.remaining_seconds():
                    return False, "wall_clock_budget_exhausted"
                return True, ""

            available = _available_tools()
            enum_crawled = any(
                row["spec_id"] == spec.id and row["tool"] == CRAWL_TOOL for row in self.broker.results
            )
            pending_now = [action for state in states.values() for action in state.pending_actions()]
            if (
                not enum_crawled
                and CRAWL_TOOL in available
                and dispatched_this_call < max_actions
                and total_dispatched < max_total
            ):
                needed = self._crawl_tool_allowance_needed(spec)
                ready, gap_reason = _budget_ready(needed)
                if ready:
                    crawl_args: dict[str, Any] = {"target": spec.target, "max_pages": 12}
                    before_results = len(self.broker.results)
                    try:
                        self.broker.invoke(CRAWL_TOOL, crawl_args)
                    except BudgetError:
                        raise
                    except ValueError as exc:
                        error = (
                            {"error": "session_binding_mismatch", "registered_session_checks": self.broker.session_checks(spec)}
                            if isinstance(exc, SessionBindingError)
                            else {"error": "tool invocation denied"}
                        )
                        if isinstance(exc, ArchiveSizeError):
                            self.add_gap(spec, "archive_size_limit_exceeded", "archive")
                        err_view = self.broker.view(error)
                        self.broker.results.append({"spec_id": spec.id, "tool": CRAWL_TOOL, "arguments": {}, **err_view})
                        dump(self.broker.private / "python-tool-results.json", self.broker.results)
                        if policy.consecutive_failures.get(spec.id, 0) >= 2:
                            raise BudgetError("consecutive_tool_failure_limit")
                    else:
                        if len(self.broker.results) > before_results:
                            continued = True
                            dispatched_this_call += 1
                            total_dispatched += 1
                        states = self.hydrate_discovery_state(spec)
                        for state_obj in states.values():
                            state_obj.continuation["last_reason"] = reason
                        self.save_checkpoint()
                elif not pending_now and gap_reason:
                    self.add_gap(spec, gap_reason, "admission_budget")

            pending_now = [action for state in states.values() for action in state.pending_actions()]
            has_any_actions = any(state.actions for state in states.values())
            if (
                not pending_now
                and not has_any_actions
                and "kali-tools_curl_request" in available
                and dispatched_this_call < max_actions
                and total_dispatched < max_total
            ):
                ready, gap_reason = _budget_ready(1)
                if ready:
                    curl_schema = available["kali-tools_curl_request"]
                    props = curl_schema.get("properties") if isinstance(curl_schema, dict) else {}
                    curl_args: dict[str, Any] = {"url": spec.target}
                    if isinstance(props, dict) and "follow_redirects" in props:
                        curl_args["follow_redirects"] = False
                    try:
                        self.broker.invoke("kali-tools_curl_request", curl_args)
                    except BudgetError:
                        raise
                    except ValueError as exc:
                        if isinstance(exc, ArchiveSizeError):
                            self.add_gap(spec, "archive_size_limit_exceeded", "archive")
                        err_view = self.broker.view({"error": "tool invocation denied"})
                        self.broker.results.append({"spec_id": spec.id, "tool": "kali-tools_curl_request", "arguments": {}, **err_view})
                        dump(self.broker.private / "python-tool-results.json", self.broker.results)
                        if policy.consecutive_failures.get(spec.id, 0) >= 2:
                            raise BudgetError("consecutive_tool_failure_limit")
                    else:
                        continued = True
                        dispatched_this_call += 1
                        total_dispatched += 1
                        states = self.hydrate_discovery_state(spec)
                        self.save_checkpoint()
                elif gap_reason:
                    self.add_gap(spec, gap_reason, "admission_budget")

            registered_identities = {item["identity"] for item in self.broker.session_checks(spec)}
            while dispatched_this_call < max_actions and total_dispatched < max_total:
                available = _available_tools()
                candidates = []
                for state_obj in states.values():
                    for action in state_obj.pending_actions():
                        candidates.append((state_obj, action))
                if not candidates:
                    break
                candidates.sort(key=lambda pair: (
                    0 if pair[1].get("link_relation") in {"pagination", "next", "json_link", "schema"} else 1,
                    0 if urlsplit(pair[1]["url"]).path.lower().endswith((".js", ".mjs", ".json")) else 1,
                    int(pair[1].get("continuation_depth", 0)),
                    pair[1]["route_shape"],
                    pair[1]["action_id"],
                ))
                state_obj, action = candidates[0]
                action_id = action["action_id"]
                identity_ref = action["identity_ref"]
                if identity_ref == "anon":
                    if "kali-tools_curl_request" in available:
                        tool_name = "kali-tools_curl_request"
                        curl_schema = available[tool_name]
                        props = curl_schema.get("properties") if isinstance(curl_schema, dict) else {}
                        tool_args = {"url": action["url"]}
                        if isinstance(props, dict) and "follow_redirects" in props:
                            tool_args["follow_redirects"] = False
                        if isinstance(props, dict) and "method" in props and action["method"] != "GET":
                            tool_args["method"] = action["method"]
                        needed = 1
                    elif CRAWL_TOOL in available:
                        tool_name = CRAWL_TOOL
                        tool_args = {"target": action["url"], "max_pages": 6}
                        needed = self._crawl_tool_allowance_needed(spec)
                    else:
                        break
                else:
                    if identity_ref not in registered_identities:
                        state_obj.mark_blocked(action_id, reason_code="missing_observed_identity_binding")
                        self.save_checkpoint()
                        continue
                    if CRAWL_TOOL in available:
                        tool_name = CRAWL_TOOL
                        tool_args = {
                            "target": action["url"],
                            "max_pages": 6,
                            "session_target": spec.target,
                            "identity": identity_ref,
                        }
                        needed = self._crawl_tool_allowance_needed(spec, identity_ref)
                    else:
                        state_obj.mark_blocked(action_id, reason_code="authenticated_discovery_requires_crawl_or_access")
                        self.save_checkpoint()
                        continue

                ready, gap_reason = _budget_ready(needed)
                if not ready:
                    if gap_reason:
                        self.add_gap(spec, gap_reason, "admission_budget")
                    break

                state_obj.mark_dispatched(action_id)
                state_obj.continuation["dispatched_count"] = int(state_obj.continuation.get("dispatched_count", 0)) + 1
                state_obj.continuation["last_reason"] = reason
                self.save_checkpoint()
                try:
                    view = self.broker.invoke(tool_name, tool_args)
                except BudgetError:
                    state_obj.mark_indeterminate(action_id, reason_code="discovery_budget_exhausted")
                    self.save_checkpoint()
                    raise
                except ValueError as exc:
                    error = (
                        {"error": "session_binding_mismatch", "registered_session_checks": self.broker.session_checks(spec)}
                        if isinstance(exc, SessionBindingError)
                        else {"error": "tool invocation denied"}
                    )
                    if isinstance(exc, ArchiveSizeError):
                        self.add_gap(spec, "archive_size_limit_exceeded", "archive")
                    err_view = self.broker.view(error)
                    self.broker.results.append({"spec_id": spec.id, "tool": tool_name, "arguments": {}, **err_view})
                    dump(self.broker.private / "python-tool-results.json", self.broker.results)
                    state_obj.mark_blocked(action_id, reason_code="discovery_execution_denied")
                    self.save_checkpoint()
                    if policy.consecutive_failures.get(spec.id, 0) >= 2:
                        raise BudgetError("consecutive_tool_failure_limit")
                    continue

                continued = True
                dispatched_this_call += 1
                total_dispatched += 1
                states = self.hydrate_discovery_state(spec)
                current = states.get(state_obj.key, state_obj).actions.get(action_id)
                if current is not None and current["status"] == "dispatched":
                    res = view.get("result") if isinstance(view, dict) else {}
                    if isinstance(res, dict) and (res.get("error") or res.get("ok") is False):
                        states.get(state_obj.key, state_obj).mark_blocked(
                            action_id, reason_code=str(res.get("reason_code") or "tool_error")[:96]
                        )
                    elif isinstance(res, dict) and res.get("execution_failed"):
                        states.get(state_obj.key, state_obj).mark_indeterminate(
                            action_id, reason_code="execution_failed"
                        )
                    else:
                        states.get(state_obj.key, state_obj).mark_completed(
                            action_id,
                            result_artifact=view.get("content_ref", {}).get("path") if isinstance(view, dict) else None,
                            result_sha256=view.get("content_ref", {}).get("sha256") if isinstance(view, dict) else None,
                        )
                self.save_checkpoint()

            for state_obj in states.values():
                if state_obj.pending_actions():
                    state_obj.continuation["has_more_pending"] = True
            self.save_checkpoint()
        finally:
            policy.host_continuing.discard(spec.id)
            dump(self.broker.private / "runtime-policy.json", policy.snapshot())
        return continued

    def dispatch_access_validation(self, spec):
        """An early summary cannot bypass the admitted, budgeted validation step."""
        if spec.phase != "access" or spec.references or spec.compiled_workflows or spec.id in self.access_dispatches:
            return False
        policy = self.broker.runtime_policy
        candidates = self.plan_candidates(spec)
        pending = [row for row in candidates if row["eligible"] and not row["evidence_accepted"]
                   and not row.get("dispatch_started")
                   and (not row["executed"] or self.deterministic_unaccepted_slice(spec, row))]
        idor_pending = [row for row in pending if row["vector"] == "access-idor"]
        param_pending = [row for row in pending if row["param"]]
        self._last_scheduler_deferred = []
        if param_pending:
            param_pending = self.parameter_continuation(spec, candidates, param_pending)
        pending = [*idor_pending, *param_pending]
        for deferred_row in getattr(self, "_last_scheduler_deferred", []):
            self.add_gap(spec, "deferred_budget", "admission_budget", deferred_row)
        # A model-selected slice spent the same rate window as host slices.
        # Only an actual task-bound executor receipt establishes that history.
        dispatched = any(row.get("task_spec_id") == spec.id and row.get("origin") == "solver"
                         and row["tool"] in {
                             "hunter_run_web_loop",
                             "validator_validate_sqli",
                             "validator_validate_ssti",
                             "validator_validate_path_traversal",
                             "validator_validate_xss_reflection",
                             "validator_validate_open_redirect",
                             "validator_validate_business_logic",
                         }
                         for row in self.broker.tools)
        continued = False
        policy.host_finalizing.add(spec.id)
        try:
            for index, row in enumerate(pending):
                if row["evidence_accepted"]:
                    continue
                if not self.admit_candidate(spec, row):
                    reason = row["reason_code"]
                    if reason in {"candidate_prerequisite_or_admission_denied", "session_not_recently_verified"}:
                        continue
                    for remaining in pending[index:]:
                        self.add_gap(spec, reason, "admission_budget", remaining)
                    view = self.broker.view({"status": "not_tested", "reason_code": reason,
                                             "pending_batches": [item["identity_ref"] for item in pending[index:]]})
                    self.broker.results.append({"spec_id": spec.id, "tool": "host_access_batch", "arguments": {}, **view})
                    dump(self.broker.private / "python-tool-results.json", self.broker.results)
                    break
                # Reuse the existing rate-window backoff; it never changes rate
                # policy. All actual requests still pass the same wire gates.
                rate_waited = dispatched
                if dispatched:
                    pending_tools = getattr(self, "_pending_rate_tools", None)
                    if not isinstance(pending_tools, dict):
                        pending_tools = {}
                        self._pending_rate_tools = pending_tools
                    row_args = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}
                    estimated_weight: int | None = None
                    if row["tool"] == "hunter_run_web_loop":
                        if row_args.get("blind_discovery"):
                            estimated_weight = max(
                                int(row_args.get("blind_max_requests") or 24),
                                int(row_args.get("max_validations") or 0),
                            )
                        elif row_args.get("validation_profile"):
                            max_val = int(row_args.get("max_validations") or 16)
                            fuzz_lim = int(row_args.get("fuzz_limit") or 4)
                            estimated_weight = max(36, max_val * 2 + fuzz_lim)
                            for prev_exec in reversed(self.broker.tools):
                                if (prev_exec.get("task_spec_id") == spec.id
                                        and prev_exec.get("tool") == "hunter_run_web_loop"):
                                    prev_receipt = json.loads(Path(prev_exec["artifact"]).read_bytes())
                                    prev_cost = (prev_receipt.get("execution") or {}).get("actual_request_cost")
                                    if type(prev_cost) is int and prev_cost > 0:
                                        estimated_weight = max(estimated_weight, prev_cost + 6)
                                        break
                    pending_tools[spec.id] = (row["tool"], estimated_weight) if estimated_weight else row["tool"]
                    try:
                        waited_ok = self.wait_access_rate_window(spec)
                    finally:
                        pending_tools.pop(spec.id, None)
                    if not waited_ok:
                        for remaining in pending[index:]:
                            self.add_gap(spec, "insufficient_time_for_rate_window", "admission_budget", remaining)
                        break
                    waited_map = getattr(self, "_last_rate_wait_elapsed", None)
                    if isinstance(waited_map, dict) and spec.id in waited_map:
                        rate_waited = bool(waited_map.pop(spec.id))
                if not self.refresh_expiring_access_sessions(spec, row, rate_window_elapsed=rate_waited):
                    continue
                if not self.admit_candidate(spec, row):
                    # Time spent in backoff does not extend session freshness
                    # or preserve a previous admission preview's authority.
                    continue
                # Durable pre-dispatch intent. If interrupted, run() leaves the
                # entire running TaskSpec inconclusive; resume never replays it.
                exec_ticket = None
                if hasattr(policy, "reserve_execution"):
                    try:
                        exec_ticket = policy.reserve_execution(spec, calls=1, estimated_tokens=0, uncertain=False)
                    except BudgetError as exc:
                        defer_reason = getattr(exc, "code", None) or (
                            str(exc)
                            if str(exc) in {"phase_tool_budget_exhausted", "token_budget_exhausted"}
                            else "deferred_budget"
                        )
                        for remaining in pending[index:]:
                            self.add_gap(spec, defer_reason, "admission_budget", remaining)
                        break
                row["dispatch_started"] = True
                for ident in row.get("slice_candidate_ids", []):
                    self.candidates_by_task[spec.id][ident]["dispatch_started"] = True
                self.save_checkpoint()
                before = len(self.broker.tools)
                try:
                    ticket_ctx = (
                        policy.activate_execution_ticket(exec_ticket)
                        if exec_ticket is not None and hasattr(policy, "activate_execution_ticket")
                        else contextlib.nullcontext()
                    )
                    with ticket_ctx:
                        self.broker.invoke(row["tool"], row["arguments"])
                except BudgetError:
                    self.add_gap(spec, "validator_execution_budget_exhausted", "admission_budget", row)
                    raise
                except ArchiveSizeError:
                    self.add_gap(spec, "archive_size_limit_exceeded", "archive", row)
                except ValueError:
                    self.add_gap(spec, "validator_execution_denied", "prerequisites", row)
                finally:
                    if exec_ticket is not None and hasattr(policy, "reconcile_execution"):
                        actual_calls = 1 if len(self.broker.tools) > before else 0
                        policy.reconcile_execution(
                            exec_ticket,
                            actual_calls=actual_calls,
                            actual_tokens=0,
                            measurement_valid=True,
                        )
                    row["executed"] = len(self.broker.tools) > before
                    self.refresh_candidate_evidence(spec)
                    if row.get("slice_candidate_ids"):
                        slice_leaves = [
                            self.candidates_by_task[spec.id].get(ident)
                            for ident in row["slice_candidate_ids"]
                        ]
                        has_slice_partial = any(
                            leaf is not None and (
                                leaf["evidence_accepted"]
                                or leaf.get("reason_code") == "indeterminate_leaf_outcome"
                            )
                            for leaf in slice_leaves
                        )
                        has_slice_queued = any(
                            leaf is not None and leaf.get("admitted") and not leaf["executed"]
                            for leaf in slice_leaves
                        )
                        slice_updated = False
                        for leaf in slice_leaves:
                            if leaf is not None and not leaf["evidence_accepted"] and not leaf["reason_code"]:
                                if not leaf["executed"] and (has_slice_partial or has_slice_queued):
                                    self.add_gap(spec, "remaining_leaf_not_validated", "admission_budget", leaf)
                                else:
                                    self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", leaf)
                                slice_updated = True
                        if slice_updated:
                            self.refresh_candidate_evidence(spec)
                    elif not row["evidence_accepted"] and not row["reason_code"]:
                        self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
                        self.refresh_candidate_evidence(spec)
                    self.save_checkpoint()
                dispatched = True
                continued = True
                if policy.consecutive_failures.get(spec.id, 0) >= 2:
                    raise BudgetError("consecutive_tool_failure_limit")
        finally:
            self.access_dispatches.add(spec.id)
            policy.host_finalizing.discard(spec.id)
            policy.validation_reserves.pop(spec.id, None)
            dump(self.broker.private / "runtime-policy.json", policy.snapshot())
        return continued

    def pending_parameter_batches(self, spec):
        """Host-selected parameter candidates; no previous model profile required."""
        return [row["arguments"] for row in self.plan_candidates(spec)
                if row["param"] and row["eligible"] and not row["evidence_accepted"] and not row["executed"]]

    def parse_calls(self, calls, advertised):
        """Validate the entire model batch before executing any part of it."""
        def invalid_constant(_value):
            raise ValueError("non-finite JSON number")

        def finite_float(value):
            number = float(value)
            if not math.isfinite(number):
                raise ValueError("non-finite JSON number")
            return number

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON member")
                result[key] = value
            return result

        parsed = []
        for call in calls:
            function = call["function"]
            name = function["name"]
            if name not in advertised:
                raise WorkflowError("tool_outside_advertised_phase_schema")
            try:
                args = json.loads(function.get("arguments"), parse_constant=invalid_constant, parse_float=finite_float,
                                  object_pairs_hook=unique_object)
            except (ValueError, TypeError):
                raise WorkflowError("tool_arguments_invalid_json") from None
            if not isinstance(args, dict):
                raise WorkflowError("tool_arguments_not_object")
            try:
                schema = advertised[name]
                validator = validator_for(schema)
                validator.check_schema(schema)
                # Only catalog-local references are admissible. Schema
                # validation must never fetch remote references or coerce args.
                validator(schema, registry=Registry()).validate(args)
            except (ValidationError, SchemaError, Unresolvable) as exc:
                # Validator text may contain credential-bearing argument
                # values. Keep only a stable code and value-free metadata.
                raise WorkflowError(
                    "tool_arguments_schema_invalid",
                    schema_diagnostic=_safe_schema_diagnostic(name, args, exc),
                ) from None
            parsed.append((name, args))
        return parsed

    def _record_schema_diagnostic(self, spec, diagnostic):
        if not diagnostic:
            return
        diagnostics = getattr(self, "schema_diagnostics", None)
        if diagnostics is None:
            diagnostics = []
            self.schema_diagnostics = diagnostics
        entry = {"spec_id": spec.id, **diagnostic}
        diagnostics.append(entry)
        dump(self.broker.private / "python-schema-diagnostics.json", diagnostics)

    def loop_event(self, spec, code, schema_diagnostic=None):
        event = {"spec_id": spec.id, "reason_code": code}
        self.loop_events.append(event)
        dump(self.broker.private / "python-loop-events.json", self.loop_events)
        feedback = dict(event)
        if schema_diagnostic:
            feedback["schema_diagnostic"] = schema_diagnostic
        self.protocol_feedback[spec.id] = feedback

    def phase(self, spec):
        from agent_integration import preflight
        checked = preflight(spec)
        if checked['status'] != 'ready':
            raise WorkflowError('schema_validation_failed', errors=checked['errors'])
        self.broker.tasks.active_spec = spec
        Path(spec.evidence_dir).mkdir(parents=True, exist_ok=True)
        if spec.phase == "access" and not spec.references:
            self.broker._check_handoff(spec)
        feedback = None
        while True:
            context = self.context(spec, feedback)
            body = {"model": self.model, "max_tokens": 4096, "stream": False,
                    "parallel_tool_calls": False,
                    "messages": [{"role": "system", "content": SYSTEM + (
                        'workflow_execute_compiled takes only a supplied binding_ref. The host verifies '
                        'compiled P7/P8 manifests and current source evidence; never construct HTTP chains.\n'
                        if spec.compiled_workflows else '')},
                                 {"role": "user", "content": provider_json(context).decode()}],
                    "tools": self.tool_schemas(spec)}
            response = self.broker.completion(body)
            try:
                message = response["choices"][0]["message"]
            except (KeyError, TypeError, IndexError):
                raise WorkflowError("provider_message_invalid") from None
            if not isinstance(message, dict):
                raise WorkflowError("provider_message_invalid")
            calls = message.get("tool_calls") or []
            if not isinstance(calls, list) or any(not isinstance(call, dict) or not isinstance(call.get("function"), dict)
                                                 or not isinstance(call["function"].get("name"), str) for call in calls):
                raise WorkflowError("provider_tool_calls_invalid")
            submitted = None
            if calls:
                summaries = [call for call in calls if call["function"]["name"] == SUMMARY_TOOL]
                if summaries and len(calls) != 1:
                    raise WorkflowError("summary_mixed_with_probes")
                try:
                    advertised = self.broker.advertised_tools
                    if advertised is None:
                        advertised = {tool["function"]["name"]: tool["function"]["parameters"]
                                      for tool in body["tools"]}
                    parsed = self.parse_calls(calls, advertised)
                except WorkflowError as exc:
                    if exc.code not in {"tool_arguments_invalid_json", "tool_arguments_not_object",
                                        "tool_arguments_schema_invalid"}:
                        raise
                    self._record_schema_diagnostic(spec, exc.schema_diagnostic)
                    if self.protocol_repairs.get(spec.id, 0):
                        raise WorkflowError(
                            "tool_protocol_repair_exhausted",
                            schema_diagnostic=exc.schema_diagnostic,
                        ) from None
                    self.protocol_repairs[spec.id] = 1
                    self.loop_event(spec, exc.code, schema_diagnostic=exc.schema_diagnostic)
                    continue
                self.protocol_feedback.pop(spec.id, None)
                for name, args in parsed:
                    if name == SUMMARY_TOOL:
                        submitted = args
                    else:
                        if (spec.phase == "access" and not spec.references and not spec.compiled_workflows
                                and name in {
                                    "validator_validate_sqli",
                                    "validator_validate_ssti",
                                    "validator_validate_path_traversal",
                                    "validator_validate_xss_reflection",
                                    "validator_validate_open_redirect",
                                    "validator_validate_business_logic",
                                    "hunter_run_web_loop",
                                }
                                and args.get("live", True) is not False):
                            options = self.plan_candidates(spec)
                            selected = next((row for row in options if matches_model_call(row, name, args)), None)
                            if selected is not None and selected["tool"] != name:
                                recipe = recipe_arguments(selected, name)
                                if recipe is not None:
                                    selected = {**copy.deepcopy(selected), "tool": name, "arguments": copy.deepcopy(recipe)}
                            if selected is None and name == "hunter_run_web_loop":
                                sliced = self.parameter_slice(spec, options, args.get("target", ""), args.get("validation_profile"))
                                if sliced and matches_model_call(sliced, name, args):
                                    selected = sliced
                            if selected is None or not self.admit_candidate(spec, selected):
                                self.add_gap(spec, "model_call_outside_admitted_candidate", "prerequisites")
                                self.loop_event(spec, "model_call_outside_admitted_candidate")
                                continue
                            # Defaults in third-party tool signatures are not
                            # authorization. Execute the full bounded host slice.
                            args = copy.deepcopy(selected["arguments"])
                        fingerprint = hashlib.sha256(provider_json([spec.id, name, args])).hexdigest()
                        previous = self._observations.get(fingerprint)
                        if name != READ_TOOL and previous and previous[1] >= 2:
                            # Two identical observations are retained. A third
                            # identical model request cannot spend more HTTP.
                            # Validator-internal controls and host batches are
                            # separate and are never deduplicated here.
                            self.loop_event(spec, "repeated_request_without_new_evidence")
                            self.broker.runtime_policy.finalizing.add(spec.id)
                            break
                        try:
                            view = self.broker.invoke(name, args)
                            if name == READ_TOOL and view.get("result", {}).get("reason_code") == "archive_read_no_progress":
                                self.add_gap(spec, "archive_read_no_progress", "archive", provenance=[view["result"]["content_ref"]])
                                self.loop_event(spec, "archive_read_no_progress")
                                self._discovery_stagnation[spec.id] = self._discovery_stagnation.get(spec.id, 0) + 1
                            if name != READ_TOOL and isinstance(view, dict):
                                digest = view.get("content_ref", {}).get("sha256")
                                if digest:
                                    count = previous[1] + 1 if previous and previous[0] == digest else 1
                                    self._observations[fingerprint] = (digest, count)
                        except ValueError as exc:
                            # Preserve an opaque execution failure; no exception
                            # text or credential-bearing parameters in feedback.
                            error = ({"error": "session_binding_mismatch",
                                      "registered_session_checks": self.broker.session_checks(spec)}
                                      if isinstance(exc, SessionBindingError) else {"error": "tool invocation denied"})
                            if isinstance(exc, ArchiveSizeError):
                                self.add_gap(spec, "archive_size_limit_exceeded", "archive")
                            view = self.broker.view(error)
                            self.broker.results.append({"spec_id": spec.id, "tool": name, "arguments": {}, **view})
                            dump(self.broker.private / "python-tool-results.json", self.broker.results)
                        if spec.phase == "access" and not spec.references and not spec.compiled_workflows:
                            self.plan_candidates(spec)
                        if self.broker.runtime_policy.consecutive_failures.get(spec.id, 0) >= 2:
                            raise BudgetError("consecutive_tool_failure_limit")
            else:
                try:
                    submitted = json.loads(message.get("content") or "")
                except (ValueError, TypeError):
                    submitted = "invalid JSON response"
            stagnation_dispatched = False
            if (
                spec.phase == "enum"
                and not spec.references
                and not spec.compiled_workflows
                and self._discovery_stagnation.get(spec.id, 0) >= 2
            ):
                self._discovery_stagnation[spec.id] = 0
                stagnation_dispatched = self.dispatch_discovery(spec, reason="archive_read_no_progress")
                if stagnation_dispatched and submitted is None:
                    continue
            if submitted is None:
                continue
            if stagnation_dispatched:
                continue
            if (
                spec.phase == "enum"
                and not spec.references
                and not spec.compiled_workflows
                and self._is_premature_enum_summary(spec, submitted)
                and self.dispatch_discovery(spec, reason="premature_enum_summary")
            ):
                continue
            if self.dispatch_access_validation(spec):
                # A fresh model input contains real tool output; this is not
                # a summary repair and never grants extra calls or HTTP.
                continue
            summary = self.compile_summary(spec, submitted)
            feedback = summary_feedback(summary, spec)
            if feedback["valid"]:
                path = self.broker.tasks.summary_path(spec)
                path.parent.mkdir(exist_ok=True)
                pretty = json.dumps(summary, indent=2, ensure_ascii=False, allow_nan=False).encode() + b"\n"
                if len(pretty) > 96 * 1024:
                    with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".host-", delete=False) as handle:
                        temporary = Path(handle.name)
                        try:
                            handle.write(provider_json(summary))
                            handle.flush()
                            os.replace(temporary, path)
                        finally:
                            temporary.unlink(missing_ok=True)
                else:
                    dump(path, summary)
                self.summaries[spec.id] = summary
                return summary
            summary_ref = self.broker.archive({"summary": summary, "feedback": feedback}, "invalid-summary")
            if spec.phase == "enum" and surface_errors(summary):
                # These fields are host compiled. A summary-only model repair
                # cannot produce missing observations or documentation fetches.
                surface = summary["surface"]
                code = "enum_surface_unavailable" if not surface["routes"] and not surface["params"] else "enum_surface_incomplete"
                raise WorkflowError(code, errors=feedback["errors"], summary_ref=summary_ref)
            if self.repairs.get(spec.id, 0):
                raise WorkflowError("summary_repair_exhausted", errors=feedback["errors"], summary_ref=summary_ref)
            self.repairs[spec.id] = 1
            self.broker.runtime_policy.repairing.add(spec.id)

    def verify_closure(self):
        import brain
        from evidence_trust import canonical_bytes, verify
        signed = json.loads((self.broker.workdir / "attempt-ledger.json").read_bytes())
        if not verify(canonical_bytes(signed["payload"]), signed, "python-attempt-ledger"):
            raise ValueError("attempt-ledger signature mismatch")
        payload = signed["payload"]
        required = {f"summaries/{ident}.json" for ident in PHASE_IDS} | {"handoff.json", "handoff-access.json", "object-pool.json"}
        if (payload.get("schema") != "python-attempt-ledger/1"
                or payload.get("target") != self.broker.tasks.specs[0].target
                or not required <= {row["path"] for row in payload["workflow_files"]}):
            raise ValueError("incomplete or replayed attempt-ledger snapshot")
        for spec in self.broker.tasks.specs:
            if not summary_feedback(self.broker.tasks.read_summary(spec), spec)["valid"]:
                raise ValueError("invalid final phase summary")
        import attempt_ledger as attempts
        records, errors = attempts.verify_records(attempts.read_records(attempts.ledger_path(self.broker.workdir)),
                                                  path=attempts.ledger_path(self.broker.workdir))
        if errors or records != signed["payload"]["records"]:
            raise ValueError("attempt-ledger records changed")
        for ref in [*signed["payload"]["artifacts"], *signed["payload"]["workflow_files"]]:
            raw = (self.broker.workdir / ref["path"]).read_bytes()
            import hashlib
            if hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                raise ValueError("attempt-ledger artifact changed")
        if json.loads((self.broker.workdir / "handoff.json").read_bytes()) != json.loads(
                (self.broker.workdir / "handoff-access.json").read_bytes()):
            raise ValueError("handoff changed")
        with contextlib.redirect_stdout(io.StringIO()) as captured:
            code = brain.main(["closure", "verify", "--workdir", str(self.broker.workdir)])
        dump(self.broker.private / "closure-verification.json", {"exit_code": code, "detail": captured.getvalue()})
        return code == 0

    def run(self):
        result = {"schema": SCHEMA, "status": "starting", "closure_verified": False,
                  "acceptance_passed": False}
        try:
            self.checkpoint.acquire()
            if self.resume:
                self.restore_checkpoint()
            elif self.checkpoint.path.exists():
                raise ValueError('existing workflow requires explicit resume')
            self._checkpoint_active = True
            self.broker.budget.checkpoint = self.save_checkpoint
            self.save_checkpoint()
            while True:
                self.refresh_observed_specs()
                self.save_checkpoint()
                spec = self.select_task()
                if spec is None:
                    break
                self.broker.tasks.active_spec = spec
                if spec.phase == 'access' and not spec.references:
                    try:
                        self.broker._check_handoff(spec)
                    except ValueError:
                        self.task_states[spec.id] = 'blocked'
                        self.add_gap(spec, 'missing_declared_handoff_prerequisite')
                        self.loop_event(spec, 'host_handoff_prerequisite_unavailable_NOT_TESTED')
                        self.save_checkpoint()
                        continue
                self.task_states[spec.id] = 'running'
                self.save_checkpoint()
                summary = self.phase(spec)
                if summary["status"] not in {"done", "partial"}:
                    self.task_states[spec.id] = 'blocked'
                    self.save_checkpoint()
                    continue
                if spec.phase == "enum" and 'kali-tools_ledger_prepare_handoff' in spec.tools:
                    # A repair has ended; host handoff remains a charged tool.
                    self.broker.runtime_policy.repairing.discard(spec.id)
                    self.broker.handoff()
                if spec.phase == "report" and 'kali-tools_ledger_checkpoint' in spec.tools:
                    self.broker.runtime_policy.repairing.discard(spec.id)
                    self.broker.seal()
                self.task_states[spec.id] = 'completed'
                self.save_checkpoint()
            for spec in self.broker.tasks.specs:
                if spec.id not in self.task_states:
                    self.task_states[spec.id] = 'blocked'
            if any(state != 'completed' for state in self.task_states.values()):
                result.update(status='python_inconclusive', stop_reason='unresolved_tasks_remain_NOT_TESTED')
            elif tuple(row['id'] for row in self.base_specs) == PHASE_IDS:
                self.broker.write_attempt_ledger()
                result["closure_verified"] = self.verify_closure()
                result["status"] = "python_finished_verified" if result["closure_verified"] else "closure_unverified"
            else:
                result['status'] = 'python_tasks_finished'
            self.save_checkpoint()
        except (BudgetError, ValueError, KeyError, OSError, TypeError) as exc:
            result.update(status="budget_invalid" if self.broker.budget.blocked else "python_failed",
                          error=type(exc).__name__, stop_reason=self.broker.stop_reason or getattr(
                              exc, "code", None) or (str(exc) if isinstance(exc, BudgetError) else "workflow_failed"),
                          failure_phase=self.broker.tasks.active_spec.id if self.broker.tasks.active_spec else None)
            if isinstance(exc, WorkflowError):
                result.update(summary_errors=exc.errors, failed_summary_ref=exc.summary_ref)
            active = self.broker.tasks.active_spec
            if active:
                reason = getattr(exc, "code", None) or "invalid_or_missing_signed_evidence"
                if isinstance(exc, BudgetError) and not getattr(exc, "code", None):
                    text = str(exc)
                    reason = ({"http budget exhausted": "http_budget_exhausted",
                               "wall clock budget exhausted": "wall_clock_budget_exhausted",
                               "tokens budget exhausted": "token_budget_exhausted"}.get(text)
                              or (text if text in {"context_limit_exhausted", "phase_call_budget_exhausted",
                                  "phase_tool_budget_exhausted", "consecutive_tool_failure_limit"}
                                  else "budget_admission_or_measurement_failed"))
                self.add_gap(active, reason, "admission_budget" if isinstance(exc, BudgetError) else "evidence")
            evidence_ref = getattr(exc, "evidence_ref", None)
            if evidence_ref is not None:
                result["failed_tool_ref"] = evidence_ref
            failure_payload = {
                key: result.get(key) for key in ("status", "error", "stop_reason", "failure_phase", "summary_errors", "failed_summary_ref", "failed_tool_ref")
            }
            if getattr(self, "schema_diagnostics", None):
                failure_payload["schema_diagnostics"] = list(self.schema_diagnostics)
            dump(self.broker.private / "workflow-failure.json", failure_payload)
            if self._checkpoint_active:
                self.broker.finalize_task(result["status"])
        finally:
            try:
                for spec in self.broker.tasks.specs:
                    if spec.id in self.candidates_by_task:
                        try:
                            self.refresh_candidate_evidence(spec)
                        except (ValueError, OSError, TypeError) as exc:
                            # A failed task refresh must not leave later tasks'
                            # cached acceptance visible in the final run funnel.
                            self.add_gap(spec, getattr(exc, "code", None) or
                                         "invalid_or_missing_signed_evidence", "evidence")
                            result.update(status="python_failed", stop_reason="candidate_evidence_refresh_failed")
                    if self.task_states.get(spec.id) != "completed":
                        self.add_gap(spec, "task_incomplete_or_indeterminate_no_replay")
                    for row in self.candidates_by_task.get(spec.id, {}).values():
                        if not row["evidence_accepted"] and not row["reason_code"]:
                            if row.get("dispatch_started") and not row["executed"] and self.task_states.get(spec.id) == "inconclusive":
                                self.add_gap(spec, "indeterminate_dispatch_not_replayed", "evidence", row)
                            else:
                                self.add_gap(spec, "candidate_not_executed", "admission_budget", row)
                if self._checkpoint_active:
                    self.save_checkpoint()
            except (ValueError, OSError, TypeError):
                result.update(status='python_failed', stop_reason='checkpoint_persistence_failed')
            finally:
                self._checkpoint_active = False
                self.broker.budget.checkpoint = None
                self.checkpoint.release()
            result.update(llm_calls=self.broker.calls,
                          contract_repair_count=sum(self.repairs.values()) + sum(self.protocol_repairs.values()),
                          protocol_repair_count=sum(self.protocol_repairs.values()),
                          loop_events=self.loop_events,
                          completed_phases=list(self.summaries), task_states=dict(self.task_states),
                           run_id=self.run_id, checkpoint=str(self.checkpoint.path),
                           coverage_gaps=dedup_gaps([row for rows in self.coverage_gaps.values() for row in rows]),
                           validation_funnels={ident: funnel(list(rows.values())) for ident, rows in self.candidates_by_task.items()},
                           leaf_validation_funnels={ident: leaf_funnel(self.leaf_outcomes_by_task.get(ident, [])) for ident in self.candidates_by_task},
                           pair_progress={ident: copy.deepcopy(self.pair_progress_by_task[ident]) for ident in self.candidates_by_task if ident in self.pair_progress_by_task},
                          budget=self.broker.budget.snapshot())
            dump(self.broker.private.parent / "run-result.json", result)
            dump(self.broker.private.parent / "budget.json", self.broker.budget.snapshot())
            with (self.broker.private.parent / "provider-usage.jsonl").open("w") as handle:
                for event in self.broker.budget.events:
                    if event["kind"] == "tokens":
                        handle.write(provider_json(event).decode() + "\n")
        return result
