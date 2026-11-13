"""Integrity and fail-closed contracts for enum provider context projections."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from full_agent_context import MAX_WRITE_BYTES, enum_followup_context, worker_followup_context
from full_agent_budget import compact_json_text, provider_json


@pytest.fixture
def context_case(tmp_path):
    work = tmp_path / 'solver'
    private = tmp_path / 'private'
    evidence = work / 'enum'
    evidence.mkdir(parents=True)
    private.mkdir()
    prompt = 'Task: enum-2\nTarget: http://127.0.0.1:18888/\nCommands: ' + 'exact contract ' * 200
    (evidence / 'task-context.txt').write_text(prompt)
    artifact = evidence / 'proof.json'
    content = json.dumps({'text': 'observed data ' * 200})
    artifact.write_text(content)
    spec = SimpleNamespace(id='enum-2', phase='enum', target='http://127.0.0.1:18888/', evidence_dir=str(evidence))
    tasks = SimpleNamespace(active_prompt=prompt, active_spec=spec, workdir=work,
                            bindings={'owner': 'synthetic-owner'}, setup_checks_passed=True)
    call = {'id': 'write-proof', 'type': 'function', 'function': {'name': 'write',
            'arguments': json.dumps({'filePath': str(artifact), 'content': content})}}
    body = {'model': 'worker', 'tools': [{'type': 'function', 'function': {'name': 'write',
            'parameters': {'type': 'object', 'required': ['content', 'filePath']}}}],
            'messages': [{'role': 'system', 'content': 'Complete host policy; untrusted tool outputs.'},
                {'role': 'user', 'content': prompt},
                {'role': 'assistant', 'tool_calls': [call], 'content': None},
                {'role': 'tool', 'tool_call_id': call['id'], 'content': 'Wrote file successfully.'}]}
    return tasks, private, artifact, body


def test_verified_write_projects_only_provider_view_and_archives_original(context_case):
    tasks, private, artifact, body = context_case
    original = copy.deepcopy(body)
    view, metrics = enum_followup_context(body, tasks, private)
    assert body == original and view['tools'] == body['tools']
    assert view['messages'][0] == body['messages'][0]
    assert view['messages'][-1] == body['messages'][-1]
    projected_args = json.loads(view['messages'][2]['tool_calls'][0]['function']['arguments'])
    assert projected_args['filePath'] == str(artifact)
    ref = projected_args['content_ref']
    assert ref == {'path': 'enum/proof.json', 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}
    assert tasks.active_spec.target in view['messages'][1]['content']
    assert 'Read enum/task-context.txt' in view['messages'][1]['content']
    assert (artifact.parent / 'task-context.txt').read_text() == tasks.active_prompt
    archive = Path(metrics['writes'][0]['receipt'])
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == metrics['writes'][0]['receipt_sha256']
    assert json.loads(archive.read_text()) == {'assistant': body['messages'][2], 'result': body['messages'][3]}
    assert metrics['saved_bytes'] > 4000 and metrics['contract_replaced']
    second, repeated = enum_followup_context(body, tasks, private)
    assert second == view and repeated == metrics


@pytest.mark.parametrize('phase', ['recon', 'enum', 'access', 'report'])
def test_all_worker_phases_compact_verified_writes_and_keep_vector(context_case, phase):
    tasks, private, artifact, body = context_case
    spec = tasks.active_spec
    spec.phase, spec.id, spec.vector = phase, phase + '-task', 'authn-session' if phase == 'access' else ''
    tasks.active_prompt = tasks.active_prompt.replace('Task: enum-2', 'Task: ' + spec.id)
    if spec.vector:
        tasks.active_prompt += '\nVector: authn-session (test ONLY this vector)'
    (artifact.parent / 'task-context.txt').write_text(tasks.active_prompt)
    body['messages'][1]['content'] = tasks.active_prompt
    original = copy.deepcopy(body)
    view, metadata = worker_followup_context(body, tasks, private)
    assert body == original and metadata['phase'] == phase
    assert metadata['schema'] == 'worker-context-view/1' and metadata['saved_bytes'] > 0
    text = view['messages'][1]['content']
    assert spec.id in text and spec.target in text and str(tasks.workdir) in text
    assert json.dumps(tasks.bindings, separators=(',', ':')) in text
    if spec.vector:
        assert 'Vector: authn-session (test ONLY this vector)' in text
    artifact.write_text('subsequent unverified edit')
    stale, metadata = worker_followup_context(body, tasks, private)
    assert stale == body and metadata is None


@pytest.mark.parametrize('case', ['initial', 'failed', 'missing_result', 'duplicate_result', 'duplicate_id',
    'out_of_order', 'changed', 'symlink', 'outside', 'traversal', 'secret', 'malformed', 'extra_args',
    'oversize', 'missing_contract', 'changed_contract', 'symlink_contract', 'fifo', 'unknown_prompt'])
def test_unverified_or_ambiguous_history_is_preserved(context_case, tmp_path, case):
    tasks, private, artifact, body = context_case
    messages = body['messages']
    function = messages[2]['tool_calls'][0]['function']
    args = json.loads(function['arguments'])
    if case == 'initial':
        del messages[2:]
    elif case == 'failed':
        messages[3]['content'] = 'Write failed'
    elif case == 'missing_result':
        messages.pop()
    elif case == 'duplicate_result':
        messages.append(copy.deepcopy(messages[3]))
    elif case == 'duplicate_id':
        messages[2]['tool_calls'].append(copy.deepcopy(messages[2]['tool_calls'][0]))
    elif case == 'out_of_order':
        messages[2], messages[3] = messages[3], messages[2]
    elif case == 'changed':
        artifact.write_text('later edit')
    elif case in {'symlink', 'outside', 'traversal', 'secret'}:
        if case == 'symlink':
            destination = tmp_path / 'other.json'
            artifact.rename(destination)
            artifact.symlink_to(destination)
        elif case == 'outside':
            args['filePath'] = str(tmp_path / 'other.json')
            Path(args['filePath']).write_text(args['content'])
        elif case == 'traversal':
            args['filePath'] = str(artifact.parent / '..' / 'enum' / artifact.name)
        else:
            args['filePath'] = str(artifact.with_suffix('.key'))
            Path(args['filePath']).write_text(args['content'])
        function['arguments'] = json.dumps(args)
    elif case == 'malformed':
        function['arguments'] = '{broken'
    elif case == 'extra_args':
        function['arguments'] = json.dumps({**args, 'unrecognized': True})
    elif case == 'oversize':
        args['content'] = 'x' * (MAX_WRITE_BYTES + 1)
        artifact.write_text(args['content'])
        function['arguments'] = json.dumps(args)
    elif case == 'missing_contract':
        (artifact.parent / 'task-context.txt').unlink()
    elif case == 'changed_contract':
        (artifact.parent / 'task-context.txt').write_text('changed')
    elif case == 'symlink_contract':
        contract = artifact.parent / 'task-context.txt'
        other = tmp_path / 'other.txt'
        contract.rename(other)
        contract.symlink_to(other)
    elif case == 'fifo':
        artifact.unlink()
        os.mkfifo(artifact)
    else:
        tasks.active_prompt = None
    original = copy.deepcopy(body)
    view, metrics = enum_followup_context(body, tasks, private)
    assert view == original == body and metrics is None


def test_unknown_user_text_is_retained_and_only_exact_contract_is_replaced(context_case):
    tasks, private, _, body = context_case
    body['messages'][1]['content'] = [{'type': 'text', 'text': 'Prefix\n' + tasks.active_prompt + '\nSuffix'},
                                    {'type': 'text', 'text': 'Independent user constraint'}]
    view, metrics = enum_followup_context(body, tasks, private)
    content = view['messages'][1]['content']
    assert content[0]['text'].startswith('Prefix\nTask: enum-2') and content[0]['text'].endswith('\nSuffix')
    assert content[1] == body['messages'][1]['content'][1] and metrics['contract_replaced']
    body['messages'][1]['content'] = 'Unrecognized task prose'
    view, metrics = enum_followup_context(body, tasks, private)
    assert view['messages'][1] == body['messages'][1] and not metrics['contract_replaced']


def mcp_case(tasks, private, body, *, handoff=False):
    args = {'url': tasks.active_spec.target} if not handoff else {'target': tasks.active_spec.target}
    tool = 'kali-tools_ledger_prepare_handoff' if handoff else 'kali-tools_curl_request'
    raw = json.dumps({'ok': True, 'text': 'observed ' * 300, 'pool': str(tasks.workdir / 'object-pool.json'),
                     'handoffs': {'access': str(tasks.workdir / 'handoff-access.json')}})
    call = {'id': 'mcp-proof', 'type': 'function', 'function': {'name': tool, 'arguments': json.dumps(args)}}
    body['messages'] = [*body['messages'][:2], {'role': 'assistant', 'tool_calls': [call]},
                       {'role': 'tool', 'tool_call_id': 'mcp-proof', 'content': compact_json_text(raw)}]
    path = private / 'tool-0000.json'
    path.write_text(json.dumps({'arguments': args, 'execution': {'result': {'output': raw}}, 'error': None}))
    row = {'artifact': str(path), 'tool': tool, 'task_spec_id': tasks.active_spec.id, 'origin': 'solver'}
    trusted = {'access': {'producer_spec_id': tasks.active_spec.id, 'producer_artifact': str(path),
                          'producer_artifact_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}}
    return row, trusted


@pytest.mark.parametrize('phase', ['recon', 'enum', 'access', 'report'])
@pytest.mark.parametrize('commands', [[], ['Fetch the exact target using GET; record status/headers/links',
                                        'Save observed proof to nested/evidence/proof.json']])
def test_followups_keep_commands_output_paths_and_summary_contract(context_case, phase, commands):
    tasks, private, artifact, body = context_case
    spec = tasks.active_spec
    spec.phase, spec.id, spec.commands = phase, phase + '-task', commands
    spec.evidence_dir = str(tasks.workdir / 'nested/evidence')
    Path(spec.evidence_dir).mkdir(parents=True)
    rules = ('Return exactly one JSON summary: phase,target,status,evidence,findings,next. '
             'status: done|blocked|failed|partial.\n'
             'steps [{id,status}]: done|blocked|not_tested.\n'
             'surface.id_formats: {family,format,example}; surface.docs_probes: {url,status}.')
    host_rules = ('Tools: kali-tools_curl_request\nScope: ../runtime/.codex/scope.json\n'
                  'Budget: at most 20 tool calls; stop.\n'
                  'Object pool: object-pool.json\nHandoff packet: handoff-access.json\n')
    step_rules = ('Steps (execute in order):\n'
                  '- save-proof: write nested/evidence/proof.json [optional: mark NOT TESTED if blocked]\n')
    tasks.active_prompt = ('Task: ' + spec.id + '\n' + host_rules + 'Commands:\n'
                           + ''.join('- ' + command + '\n' for command in commands)
                           + step_rules + rules + '\n' + 'host contract detail ' * 200)
    Path(spec.evidence_dir, 'task-context.txt').write_text(tasks.active_prompt)
    body['messages'][1]['content'] = tasks.active_prompt
    write_messages = copy.deepcopy(body['messages'][2:])
    row, _ = mcp_case(tasks, private, body)
    original = copy.deepcopy(body)
    first, metrics = worker_followup_context(body, tasks, private, [row])
    assert body == original and metrics['contract_replaced'] and not metrics['writes']
    # Native history remains raw; each later request projects that same history.
    body['messages'].extend(write_messages)
    original = copy.deepcopy(body)
    second, metrics = worker_followup_context(body, tasks, private, [row])
    assert body == original and metrics['contract_replaced'] and len(metrics['writes']) == 1
    for view in (first, second):
        text = view['messages'][1]['content']
        assert 'Commands:\n' in text and all('- ' + command + '\n' in text for command in commands)
        assert 'Evidence dir: nested/evidence (under Workdir)' in text
        assert f'Summary path: summaries/{spec.id}.json' in text
        assert f'Phase: {phase}' in text and rules in text
        assert host_rules in text
        assert step_rules in text
        assert 'filePath and content required' in text
    projected = json.loads(second['messages'][-2]['tool_calls'][0]['function']['arguments'])
    assert projected['filePath'] == str(artifact)
    assert projected['content_ref']['path'] == 'enum/proof.json'
    assert second['tools'] == body['tools']
    repeated, _ = worker_followup_context(body, tasks, private, [row])
    assert repeated == second


@pytest.mark.parametrize('case', ['valid', 'wrong_args', 'wrong_output', 'wrong_task', 'setup', 'failed', 'malformed'])
def test_mcp_context_anchor_requires_exact_completed_host_receipt(context_case, case):
    tasks, private, _, body = context_case
    row, _ = mcp_case(tasks, private, body)
    if case == 'wrong_args':
        body['messages'][2]['tool_calls'][0]['function']['arguments'] = '{}'
    elif case == 'wrong_output':
        body['messages'][3]['content'] = 'invented'
    elif case == 'wrong_task':
        row['task_spec_id'] = 'recon-1'
    elif case == 'setup':
        row['origin'] = 'setup'
    elif case == 'failed':
        path = Path(row['artifact'])
        receipt = json.loads(path.read_text())
        receipt['execution']['execution_failed'] = True
        path.write_text(json.dumps(receipt))
    elif case == 'malformed':
        body['messages'][2]['tool_calls'][0]['function']['arguments'] = '{broken'
    original = copy.deepcopy(body)
    view, metrics = enum_followup_context(body, tasks, private, [row])
    assert body == original
    if case == 'valid':
        assert metrics['contract_replaced'] and not metrics['writes']
        assert metrics['tool_receipts'][0]['tool_call_id'] == 'mcp-proof'
        assert view['messages'][3] == body['messages'][3]
    else:
        assert view == body and metrics is None


@pytest.mark.parametrize('trusted', [True, False])
def test_handoff_result_view_requires_host_binding_and_preserves_full_result(context_case, trusted):
    tasks, private, _, body = context_case
    row, handoffs = mcp_case(tasks, private, body, handoff=True)
    original = copy.deepcopy(body)
    view, metrics = enum_followup_context(body, tasks, private, [row], handoffs if trusted else {})
    assert body == original
    if trusted:
        result = json.loads(view['messages'][3]['content'])
        assert result['ok'] and result['handoffs'] == {'access': 'handoff-access.json'}
        ref = result['content_ref']
        stored = tasks.workdir / ref['path']
        assert stored.read_text() == body['messages'][3]['content']
        assert hashlib.sha256(stored.read_bytes()).hexdigest() == ref['sha256']
        assert metrics['tool_result_views']
        stored.write_text('changed')
        stale, metrics = enum_followup_context(body, tasks, private, [row], handoffs)
        assert stale['messages'][3] == body['messages'][3] and not metrics['tool_result_views']
    else:
        assert view['messages'][3] == body['messages'][3] and not metrics['tool_result_views']


@pytest.mark.parametrize('phase', ['access', 'report'])
def test_large_mcp_inventory_is_referenced_with_decisions_and_signatures_intact(context_case, phase):
    tasks, private, _, body = context_case
    tasks.active_spec.phase = phase
    row, _ = mcp_case(tasks, private, body)
    receipt = Path(row['artifact'])
    saved = json.loads(receipt.read_text())
    result = {'ok': True, 'target': tasks.active_spec.target,
              'validations': [{'verdict': 'CONFIRMED', 'signature': 'test-signature', 'validation_id': 'v1'}],
              'errors': ['retain error'], 'skipped': [{'reason': 'still NOT TESTED'}],
              'discover': {'inventory': ['observed entry'] * 3000}}
    emitted = provider_json(result).decode()
    saved['execution']['result']['output'] = emitted
    receipt.write_text(json.dumps(saved))
    body['messages'][-1]['content'] = emitted
    original = copy.deepcopy(body)
    view, metrics = worker_followup_context(body, tasks, private, [row])
    projected = json.loads(view['messages'][-1]['content'])
    assert body == original and metrics['saved_bytes'] > 40000
    assert projected['omitted_fields'] == ['discover'] and 'discover' not in projected
    assert all(projected[key] == result[key] for key in ['ok', 'target', 'validations', 'errors', 'skipped'])
    ref = projected['content_ref']
    artifact = tasks.workdir / ref['path']
    assert artifact.read_text() == emitted and hashlib.sha256(artifact.read_bytes()).hexdigest() == ref['sha256']
    assert json.loads(receipt.read_text())['execution']['result']['output'] == emitted
    artifact.write_text('stale inventory')
    stale, metadata = worker_followup_context(body, tasks, private, [row])
    assert stale['messages'][-1] == body['messages'][-1] and not metadata['tool_result_views']


def test_projection_wire_bytes_are_bounded_after_projection(context_case):
    from full_agent_budget import completion_request
    tasks, private, _, body = context_case
    view, _ = enum_followup_context(body, tasks, private)
    metrics = {}
    request, reserved = completion_request(view, models={'worker'}, remaining=30000,
                                           output_limit=4096, diagnostics=metrics)
    assert metrics['request_bytes'] == len(provider_json({k: v for k, v in request.items() if k != 'max_tokens'}))
    assert metrics['prompt_upper_bound'] <= metrics['request_bytes'] + 2048
    assert reserved == metrics['prompt_upper_bound'] + metrics['admitted_output_tokens']


@pytest.mark.parametrize('fault', ['changed', 'symlink', 'dangling_symlink', 'fifo', 'directory',
                                  'missing_parent', 'symlink_parent', 'outside'])
def test_large_result_artifact_faults_preserve_original_view(context_case, tmp_path, fault):
    from full_agent_context import result_view
    tasks, _, _, _ = context_case
    spec = tasks.active_spec
    emitted = provider_json({'ok': False, 'errors': ['blocked'],
                             'validations': [], 'discover': ['observed'] * 1000}).decode()
    folder = Path(spec.evidence_dir)
    path = folder / ('tool-result-' + hashlib.sha256(emitted.encode()).hexdigest() + '.json')
    outside = tmp_path / 'outside-result'
    outside.mkdir()
    if fault == 'changed':
        path.write_text('changed')
    elif fault in {'symlink', 'dangling_symlink'}:
        dest = outside / 'result.json'
        if fault == 'symlink':
            dest.write_text(emitted)
        path.symlink_to(dest)
    elif fault == 'fifo':
        os.mkfifo(path)
    elif fault == 'directory':
        path.mkdir()
    elif fault == 'missing_parent':
        spec.evidence_dir = str(folder / 'missing')
    elif fault == 'symlink_parent':
        link = tasks.workdir / 'result-link'
        link.symlink_to(outside, target_is_directory=True)
        spec.evidence_dir = str(link)
    else:
        spec.evidence_dir = str(outside)
    before = {p: p.read_bytes() for p in outside.iterdir() if p.is_file()}
    assert result_view(tasks, spec, emitted) is None
    assert {p: p.read_bytes() for p in outside.iterdir() if p.is_file()} == before


def append_write(body, artifact, content, ident):
    artifact.write_text(content)
    body['messages'].extend([
        {'role': 'assistant', 'content': None, 'tool_calls': [{'id': ident, 'type': 'function',
         'function': {'name': 'write', 'arguments': json.dumps({'filePath': str(artifact), 'content': content})}}]},
        {'role': 'tool', 'tool_call_id': ident, 'content': 'Wrote file successfully.'}])


def test_verified_overwrite_references_exact_retired_version(context_case):
    tasks, private, artifact, body = context_case
    old = artifact.read_bytes()
    _, first = worker_followup_context(body, tasks, private)
    append_write(body, artifact, 'new observed result ' * 300, 'new-write')
    original = copy.deepcopy(body)
    view, metrics = worker_followup_context(body, tasks, private)
    assert body == original and len(metrics['writes']) == 2
    args = json.loads(view['messages'][2]['tool_calls'][0]['function']['arguments'])
    assert args['filePath'] == str(artifact) and args['historical_version'] is True
    ref = args['content_ref']
    assert (tasks.workdir / ref['path']).read_bytes() == old
    assert ref['sha256'] == hashlib.sha256(old).hexdigest()
    assert metrics['writes'][0]['receipt'] == first['writes'][0]['receipt']
    assert artifact.read_text() == 'new observed result ' * 300


@pytest.mark.parametrize('fault', ['missing_receipt', 'changed_receipt', 'symlink_receipt',
                                  'failed_new_write', 'missing_new_result', 'unknown_edit'])
def test_retired_write_requires_previous_receipt_and_verified_successor(context_case, fault):
    tasks, private, artifact, body = context_case
    _, metadata = worker_followup_context(body, tasks, private)
    receipt = Path(metadata['writes'][0]['receipt'])
    append_write(body, artifact, 'new observed bytes ' * 300, 'new-write')
    if fault == 'missing_receipt':
        receipt.unlink()
    elif fault == 'changed_receipt':
        receipt.write_text('{}')
    elif fault == 'symlink_receipt':
        target = private / 'other.json'
        receipt.rename(target)
        receipt.symlink_to(target)
    elif fault == 'failed_new_write':
        body['messages'][-1]['content'] = 'Write failed'
    elif fault == 'missing_new_result':
        body['messages'].pop()
    else:
        artifact.write_text('unverified external edit')
    view, _ = worker_followup_context(body, tasks, private)
    assert view['messages'][2] == body['messages'][2]


def test_repeated_surface_writes_fit_remaining_paid_run_window(context_case):
    from full_agent_budget import BudgetError, completion_request
    tasks, private, artifact, body = context_case
    body['messages'] = body['messages'][:2]
    for version in range(12):
        content = json.dumps({'routes': [f'/item?id={version}-{index}' for index in range(250)],
                              'params': ['id'], 'status': 'observed'}, indent=2)
        append_write(body, artifact, content, f'write-{version}')
        worker_followup_context(body, tasks, private)
    original = copy.deepcopy(body)
    with pytest.raises(BudgetError):
        completion_request(body, models={'worker'}, remaining=19434, output_limit=4096)
    view, metrics = worker_followup_context(body, tasks, private)
    request, _ = completion_request(view, models={'worker'}, remaining=19434, output_limit=4096)
    assert body == original and request['max_tokens'] == 4096
    assert len(metrics['writes']) == 12
    assert metrics['saved_bytes'] > metrics['messages_bytes_before'] * 0.7
    assert sum(row['historical_version'] for row in metrics['writes']) == 11


def json_read_case(tasks, body):
    path = tasks.workdir / 'enum/full-result.json'
    source = json.dumps({'validations': [{'verdict': 'CONFIRMED', 'signature': 'exact-signature'}],
                         'errors': ['preserved error'], 'items': [{'url': f'/notes/{i}'} for i in range(100)]}, indent=4)
    path.write_text(source)
    lines = source.splitlines()
    output = (f'<path>{path}</path>\n<type>file</type>\n<content>\n'
              + '\n'.join(f'{i}: {line}' for i, line in enumerate(lines, 1))
              + f'\n\n(End of file - total {len(lines)} lines)\n</content>')
    body['messages'] = [*body['messages'][:2], {'role': 'assistant', 'tool_calls': [
        {'id': 'read-full', 'type': 'function', 'function': {'name': 'read',
         'arguments': json.dumps({'filePath': str(path), 'limit': 2000})}}]},
        {'role': 'tool', 'tool_call_id': 'read-full', 'content': output}]
    return path, output


def test_native_json_read_compacts_whitespace_without_changing_values(context_case):
    import re
    tasks, private, _, body = context_case
    path, output = json_read_case(tasks, body)
    original = copy.deepcopy(body)
    view, metrics = worker_followup_context(body, tasks, private)
    compact = re.findall(r'(?m)^\d+: (.*)$', view['messages'][-1]['content'])
    assert json.loads('\n'.join(compact)) == json.loads(path.read_text())
    assert body == original and metrics['native_read_views'] and metrics['saved_bytes'] > 0
    ref = metrics['native_read_views'][0]['artifact']
    assert (tasks.workdir / ref['path']).read_text() == output
    assert hashlib.sha256(output.encode()).hexdigest() == ref['sha256']


@pytest.mark.parametrize('fault', ['changed', 'symlink', 'fifo', 'truncated', 'partial', 'unknown',
                                  'duplicate_id', 'duplicate_result', 'out_of_order'])
def test_native_read_projection_rejects_unverified_bytes_or_bindings(context_case, fault):
    tasks, private, _, body = context_case
    path, _ = json_read_case(tasks, body)
    if fault == 'changed':
        path.write_text('{}')
    elif fault == 'symlink':
        other = tasks.workdir / 'other.json'
        path.rename(other)
        path.symlink_to(other)
    elif fault == 'fifo':
        path.unlink()
        os.mkfifo(path)
    elif fault in {'truncated', 'partial', 'unknown'}:
        body['messages'][-1]['content'] = body['messages'][-1]['content'].replace('1: {', '1: [truncated]')
    elif fault == 'duplicate_id':
        body['messages'][2]['tool_calls'].append(copy.deepcopy(body['messages'][2]['tool_calls'][0]))
    elif fault == 'duplicate_result':
        body['messages'].append(copy.deepcopy(body['messages'][-1]))
    else:
        body['messages'][2], body['messages'][3] = body['messages'][3], body['messages'][2]
    original = copy.deepcopy(body)
    view, metrics = worker_followup_context(body, tasks, private)
    assert view == body == original and metrics is None


@pytest.mark.parametrize('fault', ['missing_surface', 'wrong_target', 'malformed'])
def test_summary_errors_reach_worker_without_repairing_the_file(context_case, fault):
    tasks, private, _, body = context_case
    summary = {'phase': 'enum', 'target': tasks.active_spec.target, 'status': 'done',
               'evidence': ['enum/surface.json'], 'findings': [], 'next': 'access-3'}
    if fault == 'wrong_target':
        summary.update(target='https://outside.invalid/', surface={'routes': ['/notes'], 'params': []})
    folder = tasks.workdir / 'summaries'
    folder.mkdir()
    path = folder / 'enum-2.json'
    path.write_text('{broken' if fault == 'malformed' else json.dumps(summary))
    saved = path.read_bytes()
    body['messages'] = body['messages'][:2]
    original = copy.deepcopy(body)
    view, metrics = worker_followup_context(body, tasks, private)
    feedback = metrics['summary_feedback']
    assert not feedback['valid'] and feedback['errors']
    assert feedback['summary']['sha256'] == hashlib.sha256(saved).hexdigest()
    assert 'Host summary validation:' in view['messages'][-1]['content']
    assert body == original and path.read_bytes() == saved
    assert 'do not repeat completed probes' in feedback['action']


def test_valid_enum_requires_current_host_handoff_before_worker_finishes(context_case):
    from full_agent_context import summary_feedback
    tasks, _, _, _ = context_case
    tasks.active_spec.tools = ['kali-tools_ledger_prepare_handoff']
    folder = tasks.workdir / 'summaries'
    folder.mkdir()
    path = folder / 'enum-2.json'
    path.write_text(json.dumps({'phase': 'enum', 'target': tasks.active_spec.target, 'status': 'done',
        'evidence': ['enum/surface.json'], 'findings': [], 'next': 'access-3',
        'surface': {'routes': ['/notes'], 'params': []}}))
    feedback = summary_feedback(tasks)
    assert feedback['valid'] and not feedback['handoff_ready']
    assert 'Call kali-tools_ledger_prepare_handoff' in feedback['action']
    record = {'producer_spec_id': 'enum-2', 'target': tasks.active_spec.target,
              'summary_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    assert summary_feedback(tasks, {'access': record}) is None
    assert summary_feedback(tasks, {'other-vector': record}) is not None
    path.write_text(path.read_text() + '\n')
    assert summary_feedback(tasks, {'access': record}) is not None
