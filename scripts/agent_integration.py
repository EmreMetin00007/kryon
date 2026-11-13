"""Shared P9 dispatch and outcome contracts. No transport or reporting authority."""
from __future__ import annotations

import copy
import json
import hashlib
import re
from pathlib import Path
import sys


def current_hypothesis_result(home, dimension, state, validation_id):
    """Recheck signed validator evidence for a cached P5 terminal projection."""
    if state not in {'confirmed', 'tested_no_violation'} or not validation_id:
        return 'inconclusive'
    validator = str(Path(__file__).resolve().parents[1] / 'mcp-servers' / 'mcp-validator')
    if validator not in sys.path:
        sys.path.insert(0, validator)
    try:
        from cco_validator_core.evidence import load_validation, artifact_is_current
        record = load_validation(validation_id, directory=str(Path(home) / 'validations'))
        ctx = (record or {}).get('execution_context') or {}
        request_key = hashlib.sha256(json.dumps(ctx.get('url'), sort_keys=True, separators=(',', ':'),
                                               ensure_ascii=False).encode()).hexdigest()
        if (not record or request_key != dimension['request_key']
                or not artifact_is_current(record, trusted_root=str(Path(home) / 'validations'),
                                           expected_target=ctx.get('url', ''))):
            return 'inconclusive'
        fields = ('method', 'carrier', 'param', 'identity', 'resource_owner', 'run_id',
                  'resource_key', 'state_key', 'variant_key', 'resource_family', 'access_rule_hash')
        if any(ctx.get(k, '') != dimension.get(k, '') for k in fields):
            return 'inconclusive'
        for key in ('operation_id', 'observation_id'):
            if ctx.get(key) and ctx[key] != dimension.get(key):
                return 'inconclusive'
        kind = (record.get('binding') or {}).get('finding_type')
        wanted = dimension['hypothesis_type']
        if kind != wanted and {kind, wanted} != {'idor', 'bola'}:
            return 'inconclusive'
        verdict = 'CONFIRMED' if state == 'confirmed' else 'UNCONFIRMED'
        if record.get('verdict') != verdict or not (record.get('guard') or {}).get('transport_ok'):
            return 'inconclusive'
        return state
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        return 'inconclusive'


def references(row):
    """Carry the existing P5 key and full dimension without deriving a vector key."""
    dimension = row.get('dimension') or json.loads(row.get('dimension_json') or '{}')
    key = row.get('fingerprint', '')
    required = {'context', 'target_key', 'url', 'request_key', 'operation_id', 'method',
                'carrier', 'param', 'identity', 'resource_owner', 'run_id', 'observation_id', 'hypothesis_type'}
    if (not isinstance(dimension, dict) or not required <= dimension.keys()
            or any(not isinstance(dimension[k], str) for k in required)):
        raise ValueError('incomplete P5 hypothesis dimension')
    def digest(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                         ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    if not re.fullmatch(r'[a-f0-9]{64}', key) or digest(dimension) != key:
        raise ValueError('hypothesis reference does not match its P5 dimension')
    return {'hypothesis_ref': key, 'operation_ref': dimension['operation_id'],
            'dimension': copy.deepcopy(dimension)}


def validate_references(refs):
    if refs == {}:
        return []
    try:
        expected = references({'fingerprint': refs['hypothesis_ref'], 'dimension': refs['dimension']})
        return [] if refs == expected else ['operation/hypothesis reference mismatch']
    except (KeyError, TypeError, ValueError, ImportError):
        return ['invalid P5 operation/hypothesis references']


def preflight(spec, repair=None):
    """Validate locally; at most one structured repair of a detached TaskSpec.

    Repair may change contract syntax, never target, scope, references, tools or
    budgets. Policy/session prerequisites are handled outside this function.
    """
    from orchestration_spec import validate_spec, render_task_prompt, validate_worker_prompt

    def errors(candidate):
        try:
            found = validate_spec(candidate)
            return found or validate_worker_prompt(render_task_prompt(candidate))
        except (TypeError, ValueError, AttributeError):
            return ['invalid task schema']

    current = copy.deepcopy(spec)
    found = errors(current)
    attempts = 0
    if found and repair is not None:
        attempts = 1
        try:
            fixed = repair(copy.deepcopy(current), {'reason_code': 'schema_validation_failed', 'errors': found})
            protected = ('id', 'phase', 'target', 'scope_ref', 'references', 'compiled_workflows', 'tools', 'max_calls',
                         'max_minutes', 'tool_profile', 'evidence_dir', 'depends_on',
                         'bash_justification', 'tool_justification', 'vector')
            if any(getattr(fixed, k) != getattr(current, k) for k in protected):
                found = ['repair changed execution authority']
            else:
                found = errors(fixed)
                current = fixed
        except Exception:
            found = ['structured task repair failed']
    return {'status': 'blocked' if found else 'ready', 'reason_code': 'schema_validation_failed' if found else '',
            'errors': found, 'repair_attempts': attempts, 'spec': current}


def normalize_outcome(task, result, *, status, requests_sent, reason=''):
    """Host measured usage and task lifecycle; raw verdicts never become findings.

    Keep the raw result alongside this projection. A successful manifest proves
    execution, not security impact or complete scope. Closure is host-owned.
    """
    if isinstance(requests_sent, bool) or not isinstance(requests_sent, int) or requests_sent < 0:
        raise ValueError('outcome requires host-measured request count')
    refs = json.loads(task.get('references_json') or '{}')
    source = 'web_loop' if task.get('tool_name') == 'hunter_run_web_loop' else (
        'manifest' if task.get('tool_name') == 'chain_runner_execute' else 'task')
    raw = result if isinstance(result, dict) else {}
    report = raw.get('output', raw)
    if isinstance(report, str):
        try:
            report = json.loads(report)
        except ValueError:
            report = {}
    if not isinstance(report, dict):
        report = {}
    plan_only = raw.get('executed') is False or report.get('mode') in {'PLAN', 'PLAN_ONLY', 'dry_run'}
    artifacts = []
    for key in ('artifact', 'evidence_path', 'replay_evidence_hash', 'manifest_hash'):
        value = report.get(key)
        if isinstance(value, str) and value:
            artifacts.append({'kind': key, 'ref': value})
    return {'schema': 'agent-outcome/1', 'source': source, 'references': refs,
            'task_completion': status, 'run_closure': 'open', 'scope_completion': 'incomplete',
            'execution': 'not_tested' if plan_only or not requests_sent else 'tested',
            'test_result': 'inconclusive', 'reportable': False,
            'reason_code': ('blocked_budget' if 'budget' in reason.lower() else
                            'schema_validation_failed' if 'schema' in reason.lower() else
                            'blocked_prerequisite') if status == 'blocked' else '',
            'reason': str(reason),
            'requests_sent': requests_sent, 'artifacts': artifacts}
