"""Regressions for native-a895ydyz ledger repair and recon budget overrun."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import full_agent_launcher as launcher
from full_agent_budget import BudgetError, SharedBudget, completion_request, provider_json
from full_agent_history import bounded_history
from full_agent_runtime_policy import RuntimePolicy
from full_agent_tasks import NativeTasks
from orchestration_spec import render_task_prompt
from test_bounded_autonomy import _batch_run
from test_full_agent_preflight import broker as broker, mock_provider, no_network as no_network


def activate(broker, phase='recon'):
    broker.budget = SharedBudget(tokens=150000)
    broker.tasks = NativeTasks(launcher.bootstrap_plan('http://127.0.0.1:18765/', broker.workdir),
                               broker.workdir, {})
    spec = next(s for s in broker.tasks.specs if s.phase == phase)
    broker.tasks.scaffold(spec, prompt=render_task_prompt(spec, scaffolded=True, compact=True))
    broker.runtime_policy = RuntimePolicy(broker.budget)
    return spec


def worker_body(broker):
    spec = broker.tasks.active_spec
    return {'model': 'model', 'max_tokens': 4096,
            'messages': [{'role': 'system', 'content': 'Keep scope and validation gates.'},
                         {'role': 'user', 'content': broker.tasks.active_prompt}],
            'tools': [{'type': 'function', 'function': {'name': tool,
                      'parameters': {'type': 'object'}}}
                      for tool in [*spec.tools, 'read', 'write', 'edit', 'bash']]}


def test_recon_cannot_start_the_paid_ledger_error_path(broker, monkeypatch):
    spec = activate(broker)
    assert 'kali-tools_ledger_attempt_add_batch' not in spec.tools
    assert not broker.gate({'tool': 'kali-tools_ledger_attempt_add_batch', 'args': {}})['allowed']
    with pytest.raises(ValueError, match='outside active TaskSpec'):
        broker.call_tool('kali-tools', 'ledger_attempt_add_batch', {'items_json': '[{}]'})
    sink = {}
    mock_provider(monkeypatch, broker, {'choices': [{'message': {'content': 'offline'}}],
                  'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
                  request_sink=sink)
    broker.completion(worker_body(broker))
    names = {row['function']['name'] for row in sink['payload']['tools']}
    assert 'kali-tools_ledger_attempt_add_batch' not in names


def test_handoff_schema_exposes_exact_opaque_bindings_without_rewriting_execution(broker, monkeypatch):
    activate(broker, 'enum')
    broker.tasks.bindings = {'member-a': {'target': 'http://127.0.0.1:18765/', 'role': 'member',
                                        'test_data_only': True, 'owned_objects_private': True}}
    body = worker_body(broker)
    original = copy.deepcopy(body)
    sink = {}
    mock_provider(monkeypatch, broker, {'choices': [{'message': {'content': 'offline'}}],
                  'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
                  request_sink=sink)
    broker.completion(body)
    function = next(t['function'] for t in sink['payload']['tools']
                    if t['function']['name'] == 'kali-tools_ledger_prepare_handoff')
    field = function['parameters']['properties']['session_bindings_json']
    assert field['enum'] == [provider_json(broker.tasks.bindings).decode()]
    assert 'session_bindings_json' in function['parameters']['required']
    assert body == original
    assert not broker.executor.tasks


@pytest.mark.parametrize('added', [0, 1, 2, 3, 4])
def test_paid_ledger_inputs_report_all_remaining_defects(tmp_path, monkeypatch, added):
    server, run = _batch_run(tmp_path, monkeypatch)
    # The five recorded recon retries added these fields one at a time.
    fields = [('vector', 'GET'), ('endpoint', 'http://127.0.0.1:18765/'),
              ('identity', 'anon'), ('verdict', 'observed')]
    item = {'task': 'recon-1', 'phase': 'recon', 'status': 'done', 'evidence': 'recon/home-get.txt'}
    item.update(fields[:added])
    row, = server.ledger_attempt_add_batch_impl(str(run), [item])['results']
    assert row['ok'] is False
    expected = [f'attempt {key} must be a non-empty string' for key, _ in fields[added:]]
    assert row['errors'] == [*expected, 'attempt status must be an integer or omitted']
    assert not (run / 'attempts.jsonl').exists()
    # A single corrected retry creates a real signed record; no claim of
    # security coverage comes from recon's operational GET status.
    good = dict(fields, status=200, artifact='recon/home-get.txt')
    result, = server.ledger_attempt_add_batch_impl(str(run), [good])['results']
    assert result['ok'] and result['seq'] == 1


def test_access_ledger_schema_survives_compact_contract(broker):
    spec = activate(broker, 'access')
    prompt = render_task_prompt(spec, scaffolded=True, compact=True)
    assert 'Required nonempty strings: vector,endpoint,identity,verdict' in prompt
    assert 'never "done"' in prompt and 'at most one corrected retry' in prompt


def test_recorded_recon_overrun_is_refused_without_dispatch(broker):
    spec = activate(broker)
    ticket = broker.budget.reserve('tokens', 70977)
    broker.budget.settle(ticket, 70977, runtime_phase='recon', task_spec_id=spec.id)
    with pytest.raises(BudgetError):
        broker.completion(worker_body(broker))
    assert broker.stop_reason == 'phase_token_budget_exhausted'
    assert broker.calls == 0 and broker.budget.available('tokens') == 79023
    assert broker.budget.snapshot()['reserved']['tokens'] == 0
    assert broker.provider_requests[-1]['runtime_allowance']['phase_token_limit'] == 30000


def test_phase_allowances_and_finish_reserve_leave_later_phases_funded(broker, monkeypatch):
    spec = activate(broker)
    limits = broker.runtime_policy.limits
    assert limits == {'recon': 30000, 'enum': 45000, 'access': 37500, 'report': 22500, 'planner': 15000}
    assert sum(limits.values()) == 150000
    ticket = broker.budget.reserve('tokens', 21000)
    broker.budget.settle(ticket, 21000, runtime_phase='recon', task_spec_id=spec.id)
    sink = {}
    mock_provider(monkeypatch, broker, {'choices': [{'message': {'content': 'offline'}}],
                  'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
                  request_sink=sink)
    broker.completion(worker_body(broker))
    info = broker.provider_requests[-1]['runtime_allowance']
    assert info['finalizing'] and 'FINALIZE NOW' in sink['payload']['messages'][-1]['content']
    assert 'kali-tools_curl_request' not in {t['function']['name'] for t in sink['payload']['tools']}
    with pytest.raises(ValueError, match='finalization'):
        broker.call_tool('kali-tools', 'curl_request', {'url': spec.target})
    assert broker.budget.available('tokens') >= sum(limits[p] for p in ('enum', 'access', 'report', 'planner'))
    assert broker.budget.snapshot()['events'][-1]['runtime_phase'] == 'recon'


def test_provider_and_tool_limits_do_not_reset_when_spec_is_reused(broker):
    spec = activate(broker)
    policy = broker.runtime_policy
    for _ in range(spec.max_calls):
        policy.check_tool(spec, 'write')
    with pytest.raises(BudgetError, match='phase_tool'):
        policy.check_tool(copy.deepcopy(spec), 'write')
    for _ in range(3):
        info = policy.prepare(spec, 3000)
        assert info['finalizing']
        policy.admitted(info)
    with pytest.raises(BudgetError, match='phase_call'):
        policy.prepare(copy.deepcopy(spec), 3000)


def test_two_failed_ledger_calls_disable_further_repair_but_success_resets(broker):
    spec = activate(broker, 'access')
    policy = broker.runtime_policy
    tool = 'kali-tools_ledger_attempt_add_batch'
    failed = {'result': {'output': json.dumps({'results': [{'ok': False, 'error': 'bad schema'}]})}}
    policy.record_result(spec, tool, failed)
    assert tool in policy.allowed_tools(spec)
    policy.record_result(spec, tool, {'result': {'output': json.dumps({'results': [{'ok': True}]})}})
    policy.record_result(spec, tool, failed)
    assert tool in policy.allowed_tools(spec)
    policy.record_result(spec, tool, failed)
    assert tool not in policy.allowed_tools(spec)
    with pytest.raises(ValueError, match='unavailable'):
        broker.call_tool('kali-tools', 'ledger_attempt_add_batch', {'workdir': str(broker.workdir), 'items_json': '[{}]'})
    assert not broker.executor.tasks and broker.calls == 0
    assert tool in policy.prepare(spec, 3000)['disabled_tools']


def test_clean_negative_validator_results_do_not_disable_validation(broker):
    spec = activate(broker, 'access')
    policy = broker.runtime_policy
    tool = 'validator_validate_open_redirect'
    for _ in range(3):
        policy.record_result(spec, tool, {'result': {'output': json.dumps({
            'ok': False, 'verdict': 'tested_clean', 'confirmed': False})}})
    assert tool in policy.allowed_tools(spec)


def test_enum_keeps_tools_for_three_session_checks_summary_and_handoff(broker):
    spec = activate(broker, 'enum')
    policy = broker.runtime_policy
    policy.tool_calls[spec.id] = spec.max_calls - 6
    assert policy.prepare(spec, 4000)['finalizing']
    assert 'kali-tools_curl_request' not in policy.allowed_tools(spec)
    for tool in ['validator_session_vault_check'] * 3 + ['write', 'kali-tools_ledger_prepare_handoff', 'read']:
        policy.check_tool(spec, tool)
    assert policy.tool_calls[spec.id] == spec.max_calls


def test_batched_enum_probes_cannot_spend_reserved_closure_tools(broker):
    spec = activate(broker, 'enum')
    policy = broker.runtime_policy
    threshold = spec.max_calls - 6
    policy.tool_calls[spec.id] = threshold - 1
    policy.check_tool(spec, 'kali-tools_curl_request')
    # The same provider response's next probe must hit the boundary now.
    for _ in range(3):
        with pytest.raises(ValueError, match='finalization'):
            policy.check_tool(spec, 'kali-tools_curl_request')
    assert policy.tool_calls[spec.id] == threshold
    assert spec.id in policy.finalizing
    assert spec.max_calls - policy.tool_calls[spec.id] == 6
    for tool in ['validator_session_vault_check'] * 3 + ['write', 'kali-tools_ledger_prepare_handoff', 'read']:
        policy.check_tool(spec, tool)
    assert policy.tool_calls[spec.id] == spec.max_calls
    with pytest.raises(BudgetError, match='phase_tool'):
        policy.check_tool(spec, 'write')


def test_enum_can_use_one_provider_turn_per_reserved_closure_tool(broker):
    spec = activate(broker, 'enum')
    policy = broker.runtime_policy
    policy.calls[spec.id] = 5
    policy.tool_calls[spec.id] = spec.max_calls - 6
    original_limits = dict(policy.limits)
    for tool in ['validator_session_vault_check'] * 3 + ['write', 'kali-tools_ledger_prepare_handoff', 'read']:
        info = policy.prepare(spec, 4000)
        assert info['finalizing'] and info['provider_call_limit'] == 16
        policy.admitted(info)
        policy.check_tool(spec, tool)
    assert policy.calls[spec.id] == 11 and policy.finalization_calls[spec.id] == 6
    assert policy.limits == original_limits and sum(policy.limits.values()) == 150000
    with pytest.raises(BudgetError, match='phase_call'):
        policy.prepare(spec, 4000)


def test_526_token_completion_is_rejected_before_dispatch():
    body = {'model': 'model', 'messages': [{'role': 'user', 'content': 'finish'}], 'max_tokens': 4096}
    metrics = {}
    completion_request(body, models={'model'}, remaining=100000, diagnostics=metrics)
    with pytest.raises(BudgetError, match='insufficient tokens'):
        completion_request(body, models={'model'}, remaining=metrics['prompt_upper_bound'] + 526,
                           minimum_output_tokens=1024)


def history_case(tmp_path):
    work, evidence = tmp_path / 'solver', tmp_path / 'solver/recon'
    evidence.mkdir(parents=True)
    prompt = 'Task: recon-1\nCommands:\n- Fetch root\nSummary path: summaries/recon-1.json'
    (evidence / 'task-context.txt').write_text(prompt)
    tasks = SimpleNamespace(workdir=work, active_prompt=prompt,
                            active_spec=SimpleNamespace(id='recon-1', evidence_dir=str(evidence)))
    messages = [{'role': 'system', 'content': 'Scope; require signed validation.'},
                {'role': 'user', 'content': prompt}]
    for n in range(8):
        messages.extend([{'role': 'assistant', 'content': 'reasoning ' * 500,
            'tool_calls': [{'id': f'call-{n}', 'function': {'name': 'kali-tools_curl_request',
                'arguments': json.dumps({'url': f'http://127.0.0.1:18765/{n}', 'method': 'GET'})}}]},
            {'role': 'tool', 'tool_call_id': f'call-{n}', 'content': json.dumps({
                'ok': False, 'error': 'observed schema error', 'signature': 'a' * 128,
                'observations': 'raw response ' * 200})}])
    return tasks, {'model': 'model', 'messages': messages}


def test_large_history_keeps_contract_recent_turns_and_exact_signed_error_bytes(tmp_path):
    tasks, body = history_case(tmp_path)
    original = copy.deepcopy(body)
    view, receipt = bounded_history(body, tasks, max_bytes=24000)
    assert body == original and view['messages'][:2] == body['messages'][:2]
    assert view['messages'][-4:] == body['messages'][-4:]
    assert len(provider_json(view['messages'])) < 24000 and receipt['saved_bytes'] > 40000
    assert len(receipt['archives']) == 6
    for n, ref in enumerate(receipt['archives']):
        raw = (tasks.workdir / ref['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == ref['sha256']
        assert json.loads(raw) == body['messages'][2 + 2 * n:4 + 2 * n]
    assert 'observed schema error' in view['messages'][2]['content']


def test_compact_history_bounds_index_but_keeps_exact_archives_and_instructions(tmp_path):
    tasks, body = history_case(tmp_path)
    before = copy.deepcopy(body)
    verbose, _ = bounded_history(body, tasks, max_bytes=1, recent_turns=0)
    compact, receipt = bounded_history(body, tasks, max_bytes=1, recent_turns=0, compact=True)
    assert body == before and compact['messages'][:2] == before['messages'][:2]
    assert len(provider_json(compact['messages'])) < len(provider_json(verbose['messages']))
    assert len(receipt['archives']) == 8
    for n, ref in enumerate(receipt['archives']):
        raw = (tasks.workdir / ref['path']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == ref['sha256']
        assert json.loads(raw) == before['messages'][2 + 2 * n:4 + 2 * n]
    assert 'observed schema error' in compact['messages'][2]['content']
    assert 'do not repeat probes' in compact['messages'][2]['content']


@pytest.mark.parametrize('compact', [False, True])
@pytest.mark.parametrize('bad', ['pending', 'duplicate', 'wrong_result', 'changed_contract', 'tampered_archive'])
def test_history_does_not_retire_unverifiable_turns(tmp_path, bad, compact):
    tasks, body = history_case(tmp_path)
    if bad == 'changed_contract':
        (Path(tasks.active_spec.evidence_dir) / 'task-context.txt').write_text('changed')
    elif bad == 'tampered_archive':
        _, info = bounded_history(body, tasks, max_bytes=1000, recent_turns=0)
        for ref in info['archives']:
            (tasks.workdir / ref['path']).write_text('changed')
    else:
        body['messages'] = body['messages'][:4]
        if bad == 'pending':
            body['messages'].pop()
        elif bad == 'duplicate':
            body['messages'].append(copy.deepcopy(body['messages'][-1]))
        else:
            body['messages'][-1]['tool_call_id'] = 'unrelated'
    view, info = bounded_history(body, tasks, max_bytes=1000, recent_turns=0, compact=compact)
    assert view == body and info is None


def test_uncompactable_context_stops_before_any_provider_call(broker):
    activate(broker)
    body = worker_body(broker)
    body['messages'].insert(0, {'role': 'system', 'content': 'required policy ' * 3000})
    with pytest.raises(BudgetError, match='context_limit_exhausted'):
        broker.completion(body)
    assert broker.stop_reason == 'context_limit_exhausted' and broker.calls == 0
    assert broker.budget.available('tokens') == 150000


def test_broker_bounds_history_including_its_own_allowance(broker, monkeypatch, tmp_path):
    activate(broker)
    _, historical = history_case(tmp_path)
    body = worker_body(broker)
    body['messages'].extend(historical['messages'][2:])
    sink = {}
    mock_provider(monkeypatch, broker, {'choices': [{'message': {'content': 'offline'}}],
                  'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
                  request_sink=sink)
    broker.completion(body)
    assert len(provider_json(sink['payload']['messages'])) <= 24000
    assert broker.provider_requests[-1]['prompt_upper_bound'] <= 12000
    assert broker.provider_requests[-1]['history_projections']
    assert any('Host runtime allowance:' in row.get('content', '') for row in sink['payload']['messages'])
    assert body['messages'][0] == sink['payload']['messages'][0]


def test_token_dense_history_below_byte_ceiling_still_fits_prompt_bound(broker, monkeypatch):
    from full_agent_budget import prompt_bound
    activate(broker)
    body = worker_body(broker)
    for n in range(24):
        content = ''.join(hashlib.sha256(f'{n}-{i}'.encode()).hexdigest() for i in range(8))
        body['messages'].extend([
            {'role': 'assistant', 'tool_calls': [{'id': f'dense-{n}', 'function': {
                'name': 'kali-tools_curl_request', 'arguments': json.dumps({
                    'url': f'http://127.0.0.1:18765/{n}', 'method': 'GET'})}}]},
            {'role': 'tool', 'tool_call_id': f'dense-{n}', 'content': content}])
        if prompt_bound(provider_json(body))[0] > 12000:
            break
    assert len(provider_json(body['messages'])) < 24000
    assert prompt_bound(provider_json(body))[0] > 12000
    sink = {}
    mock_provider(monkeypatch, broker, {'choices': [{'message': {'content': 'offline'}}],
                  'usage': {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110}},
                  request_sink=sink)
    broker.completion(body)
    assert broker.provider_requests[-1]['prompt_upper_bound'] <= 12000
    assert len(provider_json(sink['payload']['messages'])) <= 24000
    assert broker.provider_requests[-1]['history_projections']
