"""P7 observed business rules and exact state-effect/normal-control oracle.

These contracts describe evidence requirements; they confer no wire permission.
"""
from __future__ import annotations

import json

KINDS = frozenset({'write_authorization', 'schema_symmetry', 'idempotency_replay',
                   'sequence_step_skip', 'state_transition', 'arithmetic_invariant',
                   'offset_to_zero', 'order_permutation', 'rewrite_after_complete'})
BUSINESS_TYPES = KINDS | {'business_logic', 'price_manipulation', 'mass_assignment',
                         'workflow_bypass', 'replay', 'race_condition'}


def is_business_type(value):
    normalized = '_'.join(str(value or '').strip().lower().replace('-', ' ').split())
    return normalized in BUSINESS_TYPES


def contract_errors(contract):
    if not isinstance(contract, dict):
        return ['missing_business_rule']
    errors = []
    for field in ('expected_rule', 'alternative_explanation', 'evidence_ref',
                  'workflow_id', 'session_id', 'resource_id'):
        if not isinstance(contract.get(field), str) or not contract[field].strip():
            errors.append('missing_' + field)
    if not isinstance(contract.get('kind'), str) or contract['kind'] not in KINDS:
        errors.append('unsupported_logic_scenario')
    for role in ('control', 'probe'):
        effect = contract.get(role)
        if (not isinstance(effect, dict) or not isinstance(effect.get('field'), str)
                or not effect.get('field') or 'before' not in effect or 'after' not in effect):
            errors.append('missing_' + role + '_effect')
        elif effect['before'] == effect['after']:
            errors.append(role + '_effect_must_change')
        else:
            try:
                json.dumps(effect, allow_nan=False)
            except (TypeError, ValueError):
                errors.append('invalid_' + role + '_effect')
    return errors


def _body(record):
    if not isinstance(record, dict) or not record.get('ok'):
        return None
    status = record.get('status')
    if not isinstance(status, int) or not 200 <= status < 300:
        return None
    try:
        data = json.loads(record.get('fulltext', record.get('text', '')))
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


def _field(body, path):
    value = body
    for key in path.split('.'):
        if not isinstance(value, dict) or key not in value:
            return (False, None)
        value = value[key]
    return True, value


def _matches(effect, before, after):
    if before is None or after is None:
        return False
    b_exists, b = _field(before, effect['field'])
    a_exists, a = _field(after, effect['field'])
    return (b_exists and a_exists and type(b) is type(effect['before'])
            and type(a) is type(effect['after'])
            and b == effect['before'] and a == effect['after'])


def evaluate_business_logic(expect, steps):
    contract = expect.get('contract')
    errors = contract_errors(contract)
    if errors:
        return False, {'reason': 'missing_prerequisite', 'errors': errors}
    refs = [expect.get(k) for k in ('control_before', 'control_after', 'probe_before', 'probe_after')]
    if any(not r or r not in steps for r in refs) or len(set(refs)) != 4:
        return False, {'reason': 'missing_observations'}
    cb, ca, pb, pa = [_body(steps[r]) for r in refs]
    control = _matches(contract['control'], cb, ca)
    effect = _matches(contract['probe'], pb, pa)
    return control and effect, {'normal_control_passed': control,
                               'violation_effect_observed': effect,
                               'business_rule_ref': contract['evidence_ref'],
                               'reason': 'validated_effect' if control and effect else 'effect_or_control_mismatch'}


def evaluate_normal_control(expect, steps):
    contract = expect.get('contract')
    if contract_errors(contract):
        return False, {'reason': 'missing_business_rule'}
    before = _body(steps.get(expect.get('control_before')))
    after = _body(steps.get(expect.get('control_after')))
    passed = _matches(contract['control'], before, after)
    return passed, {'normal_control_passed': passed}


def manifest_errors(manifest):
    """Reject edited graphs that bypass controls or replace the effect oracle."""
    errors = []
    logic = manifest.get('business_logic')
    if not isinstance(logic, dict):
        return ['missing_business_logic_contract']
    contract = logic.get('contract')
    errors.extend(contract_errors(contract))
    context = manifest.get('observed_context')
    if not isinstance(context, dict) or context.get('source') != 'capture':
        return errors + ['unobserved_context']
    if not isinstance(contract, dict):
        return errors
    if any(context.get(k) != contract.get(k) for k in ('workflow_id', 'session_id', 'resource_id')):
        errors.append('business_context_mismatch')
    if manifest.get('kind') != contract.get('kind') or logic.get('oracle') != 'business_logic':
        errors.append('business_scenario_mismatch')
    steps = manifest.get('steps')
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        return errors + ['invalid_logic_steps']
    offset = 0
    for role in ('control', 'probe'):
        selected = [s for s in steps if str(s.get('id', '')).startswith(role + '-')]
        if len(selected) < 3 or steps[offset:offset+len(selected)] != selected:
            errors.append('missing_' + role + '_workflow')
            continue
        offset += len(selected)
        first, last = selected[0], selected[-1]
        if first.get('id') != role + '-before' or last.get('id') != role + '-after':
            errors.append('invalid_' + role + '_observations')
        for index, step in enumerate(selected):
            expected_phase = 'pre_state' if index == 0 else 'post_state' if index == len(selected)-1 else 'experiment'
            if step.get('lifecycle_phase') != expected_phase:
                errors.append('invalid_lifecycle_phase')
            args = step.get('args') or {}
            if not isinstance(args, dict):
                errors.append('invalid_logic_args')
                continue
            if step.get('object_url') != first.get('object_url'):
                errors.append('mismatched_fixture')
            if (not step.get('resource_id') or not step.get('resource_field')
                    or step.get('resource_id') != first.get('resource_id')
                    or step.get('resource_field') != first.get('resource_field')):
                errors.append('mismatched_resource_identity')
            if expected_phase != 'experiment':
                if step.get('tool') != 'http_get' or args.get('url') != step.get('object_url'):
                    errors.append('invalid_observer_step')
            elif step.get('tool') != 'http_post' or args.get('method') not in {'POST', 'PUT', 'PATCH'}:
                errors.append('invalid_logic_action')
            if step.get('requires') or step.get('reflect') or args.get('reflect'):
                errors.append('unsupported_logic_action_option')
            if not step.get('identity_refs'):
                errors.append('explicit_test_identity_required')
        expected = {**logic, 'oracle': 'business_control' if role == 'control' else 'business_logic'}
        if last.get('expect') != expected:
            errors.append('business_oracle_mismatch')
    if offset != len(steps):
        errors.append('unexpected_logic_steps')
    control = next((s for s in steps if s.get('id') == 'control-before'), {})
    probe = next((s for s in steps if s.get('id') == 'probe-before'), {})
    if (not control.get('resource_id') or control.get('resource_id') == probe.get('resource_id')
            or probe.get('resource_id') != context.get('resource_id')
            or control.get('object_url') == probe.get('object_url')):
        errors.append('independent_normal_control_required')
    for i, step in enumerate(steps):
        if step.get('on_success') != (steps[i+1].get('id') if i+1 < len(steps) else 'succeed'):
            errors.append('business_control_bypass')
        if step.get('on_failure') not in {'abort', 'fail'}:
            errors.append('business_failure_bypass')
    for key in ('control_before', 'control_after', 'probe_before', 'probe_after'):
        if logic.get(key) != key.replace('_', '-'):
            errors.append('business_observation_ref_mismatch')
    return errors
