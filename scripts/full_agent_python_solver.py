"""Host-owned task selection and resumable, bounded model/tool execution."""
from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import math
import re
import sys
import time
import uuid
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
                                    SESSION_CHECK_TOOL, SUMMARY_TOOL, SessionBindingError)
from full_agent_summary_feedback import summary_feedback
from orchestration_spec import COMPILED_WORKFLOW_TOOL, TaskSpec, skeleton_summary, surface_errors, validate_chain
from workflow_checkpoint import WorkflowCheckpoint, SCHEMA as CHECKPOINT_SCHEMA, file_ref
from python_candidate_runtime import (PROFILES, candidate, compact_cards, compact_gaps, dedup_gaps, funnel, gap,
                                      matches_model_call, parameter_candidates, parser_gaps, upstream_ids)

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

    def __init__(self, code, *, errors=None, summary_ref=None):
        super().__init__(code.replace("_", " "))
        self.code, self.errors, self.summary_ref = code, errors, summary_ref


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
        self.coverage_gaps = {}
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
        broker, budget, policy = self.broker, self.broker.budget, self.broker.runtime_policy
        if self.authorization_context() != self._authorization_context:
            raise ValueError('workflow authorization context changed')
        state = {'summaries': self.summaries, 'results': broker.results, 'references': broker.references,
                 'handoffs': broker.handoffs, 'tools': broker.tools, 'calls': broker.calls,
                 'repairs': self.repairs, 'protocol_repairs': self.protocol_repairs,
                 'loop_events': self.loop_events, 'observations': self._observations,
                 'access_dispatches': sorted(self.access_dispatches),
                 'batches_by_task': self.batches_by_task, 'candidates_by_task': self.candidates_by_task,
                 'coverage_gaps': self.coverage_gaps, 'branch_handoffs': broker.branch_handoffs,
                 'read_progress': broker.read_progress,
                 'policy': {key: (sorted(value) if isinstance(value, set) else value)
                            for key, value in vars(policy).items()
                            if key not in {'budget', 'tool_failures'}},
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
        self.coverage_gaps = state.get('coverage_gaps', {})
        self.broker.branch_handoffs = state.get('branch_handoffs', {})
        self.broker.read_progress = state.get('read_progress', {})
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
                self.task_states[spec.id] = 'inconclusive'
                self.summaries.pop(spec.id, None)
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
        planned = parameter_candidates(spec, records, bindings)
        provenance = [{key: record[key] for key in ("source_spec_id", "source_artifact", "source_sha256")}
                      for record in records]
        provenance = [json.loads(raw) for raw in dict.fromkeys(provider_json(row).decode() for row in provenance)]
        if records and spec.vector in ("", "access", "access-idor", "authz-idor"):
            for batch in self.batches_by_task.get(spec.id, []):
                args = {"target": spec.target, "live": True, "crawl": False,
                        "blind_discovery": True, "blind_max_requests": 24, "max_validations": 16,
                        "fuzz_limit": 0, "candidate_sample_limit": 0, "sleep_s": 0.2,
                        "session_bindings": provider_json(batch).decode()}
                planned.append(candidate(spec.id, route=spec.target, identity=list(batch), vector="access-idor",
                    tool="hunter_run_web_loop", arguments=args, provenance=provenance,
                    reason="validator_not_declared" if "hunter_run_web_loop" not in spec.tools else ""))
        if not records:
            self.add_gap(spec, "missing_declared_upstream_observations")
        elif not planned:
            self.add_gap(spec, "missing_parameter_or_synthetic_identity_pair", provenance=provenance)
        if not self.batches_by_task.get(spec.id) or spec.vector not in ("", "access", "access-idor", "authz-idor"):
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
            if row["reason_code"]:
                self.add_gap(spec, row["reason_code"], row=state[row["candidate_id"]])
        self.refresh_candidate_evidence(spec)
        return list(state.values())

    def refresh_candidate_evidence(self, spec):
        outcomes = self.broker.validation_attempts(spec)
        for row in self.candidates_by_task.get(spec.id, {}).values():
            if not row["eligible"]:
                continue
            for execution in self.broker.tools:
                if (execution.get("task_spec_id") != spec.id or execution["tool"] != row["tool"]
                        or execution.get("origin") != "solver"):
                    continue
                receipt = json.loads(Path(execution["artifact"]).read_bytes())
                args = receipt.get("arguments", {})
                expected = row["arguments"]
                fields = ("target", "validation_profile", "blind_discovery", "session_bindings") if row["tool"] == "hunter_run_web_loop" else ("target_url", "param", "method", "carrier")
                def equal(key):
                    if key == "session_bindings":
                        return json.loads(args.get(key, "{}")) == json.loads(expected.get(key, "{}"))
                    return args.get(key, {"method": "GET", "carrier": "query", "blind_discovery": False}.get(key)) == expected.get(key, {"method": "GET", "carrier": "query", "blind_discovery": False}.get(key))
                if all(equal(key) for key in fields):
                    row.update(admitted=True, executed=True)
            accepted = []
            if row["vector"] == "access-idor":
                batch: dict[str, Any] = next((batch for batch in self.batches_by_task.get(spec.id, [])
                              if list(batch) == row["identity_ref"]), {})
                if batch and self.completed_member_batch(spec, batch):
                    accepted = [item for item in outcomes if item["record"].get("execution_context", {}).get("identity") in batch
                                and item["record"].get("execution_context", {}).get("resource_owner") in batch]
            else:
                oracle = next((value[2] for value in PROFILES.values() if value[0] == row["vector"]), None)
                accepted = [item for item in outcomes if item["vector"] == row["vector"]
                    and item.get("tool", row["tool"]) == row["tool"]
                    and item["record"]["target"] == row["route"] and item["record"].get("oracle") == oracle
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("param") == row["param"]
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("method") == "GET"
                    and item.get("execution_context", item["record"].get("execution_context", {})).get("carrier") == "query"
                    and (row["identity_ref"] == "anon" and item.get("execution_context", item["record"].get("execution_context", {})).get("identity", "anon") in {"anon", "anonymous"}
                         or isinstance(row["identity_ref"], list) and item.get("execution_context", item["record"].get("execution_context", {})).get("identity") in row["identity_ref"])]
            row["evidence_accepted"] = bool(accepted)
            if accepted:
                row.update(admitted=True, executed=True, validation_state="TESTED", reason_code="",
                           evidence_refs=[{"validation_id": item["record"]["validation_id"],
                                           "source_artifact": item["source_artifact"],
                                            "source_sha256": item["source_sha256"]} for item in accepted])
                self.coverage_gaps[spec.id] = [item for item in self.coverage_gaps.get(spec.id, [])
                                               if item.get("candidate_id") != row["candidate_id"]]
            elif row["executed"]:
                row["evidence_refs"] = []
                self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)

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
        row["admitted"] = True
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

    def member_comparison_coverage(self, spec):
        """A dispatched pair needs a complete, currently signed queue to count."""
        rows = []
        shortfalls = [row["result"] for row in self.broker.results
                      if row["spec_id"] == spec.id and row["tool"] == "host_access_batch"]
        for batch in self.member_batches(spec):
            complete = self.completed_member_batch(spec, batch)
            reason = next((item["reason_code"] for item in reversed(shortfalls)
                           if list(batch) in item.get("pending_batches", [])),
                          "no_complete_current_signed_pair_queue")
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

    def completed_member_batch(self, spec, bindings):
        """Only a fully observed queue with current signed outcomes avoids replay."""
        trusted = {item["record"]["validation_id"]: item["record"]
                   for item in self.broker.validation_attempts(spec)}
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
            report = self.broker.read_reference(row["content_ref"])
            discovery = report.get("identity_discovery", {})
            if (not report.get("ok") or discovery.get("status") != "ready" or discovery.get("reasons")
                    or discovery.get("budget_limited") or report.get("errors")):
                continue
            queue = report.get("validation_queue", [])
            validations = report.get("validations", [])
            def key(item):
                return tuple(item.get(name) for name in ("url", "method", "vuln_class", "operation_id",
                                                         "resource_owner", "identity"))
            completed = {key(item) for item in validations
                         if item.get("validation_id") in trusted
                         and trusted[item["validation_id"]]["target"] == item.get("url")
                         and key(trusted[item["validation_id"]].get("execution_context", {})) == key(item)}
            if (queue and {item.get("resource_owner") for item in queue} == set(bindings)
                    and all({item.get("resource_owner"), item.get("identity")} == set(bindings) for item in queue)
                    and all(key(item) in completed for item in queue)):
                return True
        return False

    def wait_access_rate_window(self, spec):
        """Let existing request reservations expire without changing rate policy."""
        tools = ("hunter_run_web_loop", "validator_validate_idor", "validator_validate_auth_bypass",
                 "kali-tools_curl_request", "kali-tools_discover_web_surface")
        seconds = max(self.broker.engine._rate_limit_for(tool)[0] for tool in tools)
        start = self.broker.budget.clock()
        self.broker._require_open()
        if self.broker.budget.remaining_seconds() <= seconds:
            return False
        deadline = start + seconds
        while self.broker.budget.clock() < deadline:
            self.broker.closed.wait(min(1, deadline - self.broker.budget.clock()))
            self.broker._require_open()
            if not self.broker.budget.remaining_seconds():
                raise BudgetError("wall clock budget exhausted")
        view = self.broker.view({"status": "rate_window_elapsed", "window_seconds": seconds,
                                 "elapsed_seconds": self.broker.budget.clock() - start})
        self.broker.results.append({"spec_id": spec.id, "tool": "host_access_backoff", "arguments": {}, **view})
        dump(self.broker.private / "python-tool-results.json", self.broker.results)
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
        discovery = self.discovery(spec) if spec.phase in {"access", "report"} else None
        context["discovery"] = self.broker.view(discovery, "discovery") if spec.phase in {"access", "report"} and discovery else None
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
        from cco_surface_core.extract import extract_html
        base = args.get("url") or args.get("target") or spec.target
        records = []
        status = value.get("status_code", value.get("status"))
        if type(status) is int and 200 <= status < 300 and isinstance(value.get("text"), str):
            records.extend(extract_html(value["text"], base))
        surface = value.get("surface", value)
        if isinstance(surface, dict):
            for key in ("records", "work_queue", "pages", "urls_sample", "links", "internal_links"):
                for item in surface.get(key, []) if isinstance(surface.get(key), list) else []:
                    if isinstance(item, str):
                        records.append({"url": item, "method": "GET"})
                    elif isinstance(item, dict):
                        records.append(item)
        output = []
        origin = urlsplit(spec.target)
        for record in records:
            url = record.get("url") or record.get("href")
            if not isinstance(url, str):
                continue
            url = urljoin(base, url)
            parsed = urlsplit(url)
            if (parsed.scheme, parsed.netloc) != (origin.scheme, origin.netloc) or parsed.username is not None:
                continue
            params = [item for item in record.get("params", []) if isinstance(item, dict) and isinstance(item.get("name"), str)]
            names = {item["name"] for item in params}
            params.extend({"name": key, "in": "query", "sample": val} for key, val in
                          parse_qsl(parsed.query, keep_blank_values=True) if key not in names)
            output.append({"url": url, "method": record.get("method", "GET"), "params": params,
                           "source_artifact": ref["path"], "source_sha256": ref["sha256"]})
        return [json.loads(raw) for raw in dict.fromkeys(provider_json(row).decode() for row in output)]

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
            for row in candidates:
                if not row["evidence_accepted"] and not row["reason_code"]:
                    self.add_gap(spec, "invalid_or_missing_signed_evidence" if row["executed"] else "candidate_not_executed",
                                 "evidence" if row["executed"] else "admission_budget", row)
            summary["validation_funnel"] = funnel(candidates)
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
        if spec.phase == "report":
            sources = set(upstream_ids(spec, self.broker.tasks.specs))
            summary["validation_funnels"] = {ident: previous["validation_funnel"] for ident, previous in self.summaries.items()
                                             if ident in sources and "validation_funnel" in previous}
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
            summary["unfinished_work"] = unfinished
            for field in ("identity_comparisons", "identity_comparison_dimensions"):
                summary[field] = [{"phase": ident, **row} for ident, previous in self.summaries.items()
                                  if ident in sources for row in previous.get(field, [])
                                  if row["status"] == "NOT TESTED"]
            steps = summary["steps"]
            if all(isinstance(step, dict) for step in steps):
                summary["steps"] = [step for step in steps if step.get("id") != REPORT_CARRYOVER_STEP]
                summary["steps"].append({"id": REPORT_CARRYOVER_STEP, "status": "not_tested" if unfinished else "done"})
                if unfinished and summary.get("status") == "done":
                    summary["status"] = "partial"
        inherited_gaps = [row for ident in upstream_ids(spec, self.broker.tasks.specs)
                          for row in self.summaries.get(ident, {}).get("coverage_gaps", [])]
        summary["coverage_gaps"] = dedup_gaps([*inherited_gaps, *self.coverage_gaps.get(spec.id, [])])
        return summary

    def dispatch_access_validation(self, spec):
        """An early summary cannot bypass the admitted, budgeted validation step."""
        if spec.phase != "access" or spec.references or spec.compiled_workflows or spec.id in self.access_dispatches:
            return False
        policy = self.broker.runtime_policy
        candidates = self.plan_candidates(spec)
        pending = [row for row in candidates if row["eligible"] and not row["executed"] and not row["evidence_accepted"]]
        dispatched = False
        policy.host_finalizing.add(spec.id)
        try:
            for index, row in enumerate(pending):
                if row["executed"] or row["evidence_accepted"]:
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
                if dispatched and not self.wait_access_rate_window(spec):
                    for remaining in pending[index:]:
                        self.add_gap(spec, "insufficient_time_for_rate_window", "admission_budget", remaining)
                    break
                # Durable pre-dispatch intent. If interrupted, run() leaves the
                # entire running TaskSpec inconclusive; resume never replays it.
                row["dispatch_started"] = True
                self.save_checkpoint()
                before = len(self.broker.tools)
                try:
                    self.broker.invoke(row["tool"], row["arguments"])
                except BudgetError:
                    self.add_gap(spec, "validator_execution_budget_exhausted", "admission_budget", row)
                    raise
                except ValueError:
                    self.add_gap(spec, "validator_execution_denied", "prerequisites", row)
                finally:
                    row["executed"] = len(self.broker.tools) > before
                    self.refresh_candidate_evidence(spec)
                    if not row["evidence_accepted"] and not row["reason_code"]:
                        self.add_gap(spec, "invalid_or_missing_signed_evidence", "evidence", row)
                    self.save_checkpoint()
                dispatched = True
                if policy.consecutive_failures.get(spec.id, 0) >= 2:
                    raise BudgetError("consecutive_tool_failure_limit")
        finally:
            self.access_dispatches.add(spec.id)
            policy.host_finalizing.discard(spec.id)
            policy.validation_reserves.pop(spec.id, None)
            dump(self.broker.private / "runtime-policy.json", policy.snapshot())
        return dispatched

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
            except (ValidationError, SchemaError, Unresolvable):
                # Validator text may contain credential-bearing argument
                # values. Keep only a stable code in model feedback and logs.
                raise WorkflowError("tool_arguments_schema_invalid") from None
            parsed.append((name, args))
        return parsed

    def loop_event(self, spec, code):
        event = {"spec_id": spec.id, "reason_code": code}
        self.loop_events.append(event)
        dump(self.broker.private / "python-loop-events.json", self.loop_events)
        self.protocol_feedback[spec.id] = event

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
                    if self.protocol_repairs.get(spec.id, 0):
                        raise WorkflowError("tool_protocol_repair_exhausted") from None
                    self.protocol_repairs[spec.id] = 1
                    self.loop_event(spec, exc.code)
                    continue
                self.protocol_feedback.pop(spec.id, None)
                for name, args in parsed:
                    if name == SUMMARY_TOOL:
                        submitted = args
                    else:
                        if (spec.phase == "access" and not spec.references and not spec.compiled_workflows
                                and name in {"validator_validate_sqli", "validator_validate_ssti", "hunter_run_web_loop"}
                                and args.get("live", True) is not False):
                            options = self.plan_candidates(spec)
                            selected = next((row for row in options if matches_model_call(row, name, args)), None)
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
            if submitted is None:
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
            dump(self.broker.private / "workflow-failure.json", {
                key: result.get(key) for key in ("status", "error", "stop_reason", "failure_phase", "summary_errors", "failed_summary_ref", "failed_tool_ref")})
            if self._checkpoint_active:
                self.broker.finalize_task(result["status"])
        finally:
            try:
                for spec in self.broker.tasks.specs:
                    if self.task_states.get(spec.id) != "completed":
                        self.add_gap(spec, "task_incomplete_or_indeterminate_no_replay")
                    for row in self.candidates_by_task.get(spec.id, {}).values():
                        if not row["evidence_accepted"] and not row["reason_code"]:
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
                          budget=self.broker.budget.snapshot())
            dump(self.broker.private.parent / "run-result.json", result)
            dump(self.broker.private.parent / "budget.json", self.broker.budget.snapshot())
            with (self.broker.private.parent / "provider-usage.jsonl").open("w") as handle:
                for event in self.broker.budget.events:
                    if event["kind"] == "tokens":
                        handle.write(provider_json(event).decode() + "\n")
        return result
