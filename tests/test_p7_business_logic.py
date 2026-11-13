"""P7 offline integration and adversarial contract tests; no sockets/providers."""
from __future__ import annotations

import copy
import importlib.util
import json
import sqlite3
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
from action_manifest import validate_manifest  # noqa: E402
from business_logic import evaluate_business_logic  # noqa: E402
from chain_executor import ChainExecutor  # noqa: E402
from lab.business_logic_lab import IDENTITIES, KINDS, LogicLab  # noqa: E402
from workflow_compiler import _find_observer_url, compile_workflow_manifests  # noqa: E402
import write_set  # noqa: E402

spec = importlib.util.spec_from_file_location('p7_write_validate', REPO / 'scripts/write-validate.py')
write_validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(write_validate)


class AllowGate:
    def validate_tool_invocation(self, *args, **kwargs):
        return {'allowed': True}


def prepared(tmp_path, kind='idempotency_replay', *, vulnerable=True):
    lab = LogicLab(vulnerable=vulnerable)
    urls = {role: lab.setup(kind, role) for role in ('control', 'probe')}
    db = str(tmp_path / 'write_set.db')
    for url in urls.values():
        write_set.seal_object(db, object_url=url, identity_label='owner', task_ref=kind,
            run_fingerprints=[write_set.fingerprint_credentials(h) for h in IDENTITIES.values()],
            run_id='run-a', session_id='session-a', test_account=True,
            ownership_evidence={'fixture': url})
    captures = lab.capture(kind, urls, session_id='session-a')
    manifests = compile_workflow_manifests(captures)
    assert len(manifests) == 1
    context = {'db_path': db, 'run_id': 'run-a', 'session_id': 'session-a'}
    return lab, urls, captures, manifests[0], context


def run_prepared(prep, **kwargs):
    lab, urls, captures, manifest, ctx = prep
    return ChainExecutor(policy_engine=AllowGate(), sender=lab.sender,
                         identities=IDENTITIES, write_context=ctx, **kwargs).execute(manifest)


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('vulnerable', [False, True])
def test_five_scenarios_full_lifecycle(tmp_path, kind, vulnerable):
    result = write_validate.run_scenario(kind, db_path=str(tmp_path / 'ws.db'),
        run_id='run-a', session_id='session-a', vulnerable=vulnerable)
    assert result.get('validated_effect') is vulnerable, result
    assert result['unresolved_fixtures'] == []
    control = next(s for s in result['steps_executed'] if s['id'] == 'control-after')
    assert control['oracle_detail']['normal_control_passed'] is True
    for row in result['cleanup']:
        assert [e['phase'] for e in row['lifecycle']] == [
            'setup', 'own', 'pre_state', 'experiment', 'post_state', 'torn_down']
        assert all(len(e['evidence_hash']) == 64 for e in row['lifecycle'])


@pytest.mark.parametrize('teardown,expected', [('failed', 'cleanup_failed'),
    ('unknown', 'unknown'), ('exception', 'cleanup_failed')])
def test_cleanup_failure_visible(tmp_path, teardown, expected):
    result = write_validate.run_scenario('schema_symmetry', db_path=str(tmp_path / 'ws.db'),
        run_id='run-a', session_id='session-a', vulnerable=True, teardown=teardown)
    assert result['validated_effect'] is True
    assert len(result['unresolved_fixtures']) == 2
    assert {r['state'] for r in result['cleanup']} == {expected}
    for row in result['cleanup']:
        assert not write_set.mutation_permitted(str(tmp_path / 'ws.db'), row['object_url'],
            write_set.fingerprint_credentials(IDENTITIES['owner']),
            run_id='run-a', session_id='session-a')[0]


@pytest.mark.parametrize('field,value', [('run_id', 'run-b'), ('session_id', 'session-b'),
                                       ('run_id', ''), ('session_id', '')])
def test_cross_run_rejected_before_first_request(tmp_path, field, value):
    prep = prepared(tmp_path)
    prep[-1][field] = value
    result = run_prepared(prep)
    assert result['success'] is False and result['requests_sent'] == 0
    assert not prep[0].calls
    assert 'cross_run_rejected' in result['terminal_error'] or 'missing_prerequisite' in result['terminal_error']


@pytest.mark.parametrize('field,value', [('resource_id', 'other'), ('session_id', 'other'),
    ('workflow_id', 'other'), ('source', 'synthetic')])
def test_observer_binding_mismatch(tmp_path, field, value):
    _, _, captures, _, _ = prepared(tmp_path)
    probe = next(r for r in captures if r['observed_context']['capture_id'] == 'probe-0')
    probe['observed_context'][field] = value
    gaps = []
    assert compile_workflow_manifests(captures, diagnostics=gaps) == []
    assert any(g['reason'] == 'unobserved_observer' for g in gaps)


@pytest.mark.parametrize('url', ['https://p7.lab.test/other', 'http://wrong.test/objects/x',
                                'http://p7.lab.test/unrelated'])
def test_same_host_path_or_origin_is_not_observer_evidence(tmp_path, url):
    _, _, captures, _, _ = prepared(tmp_path)
    observer = next(r for r in captures if r['observed_context']['capture_id'] == 'probe-0')
    observer['url'] = url
    observer['observed_context']['response_links'] = []
    mutator = next(r for r in captures if r['observed_context']['capture_id'] == 'probe-1')
    mutator['observed_context']['response_links'] = []
    assert _find_observer_url(mutator['url'], [observer], mutator=mutator) == ('', {})


def test_observer_fallback_removed_without_context():
    assert _find_observer_url('https://shop.test/cart/submit', [
        {'url': 'https://shop.test/health', 'method': 'GET', 'resp_body': '{"total": 0}'}]) == ('', {})
    assert _find_observer_url('https://shop.test/cart/submit', []) == ('', {})


@pytest.mark.parametrize('alter', ['response_id', 'consumed_id', 'producer_id', 'missing_links',
                                  'redacted', 'synthetic', 'draft'])
def test_unproven_resource_links_never_compile(tmp_path, alter):
    _, _, captures, _, _ = prepared(tmp_path)
    observer = next(r for r in captures if r['observed_context']['capture_id'] == 'probe-0')
    for r in captures:
        if r['observed_context']['capture_id'].startswith('probe-') and r['method'] == 'POST':
            if alter == 'consumed_id':
                body = json.loads(r['req_body']); body['resource_id'] = 'foreign'; r['req_body'] = json.dumps(body)
            elif alter == 'producer_id':
                r['observed_context']['response_links'][0]['producer'] = 'not-captured'
            elif alter == 'missing_links':
                r['observed_context'].pop('response_links')
    if alter == 'response_id':
        body = json.loads(observer['resp_body']); body['id'] = 'foreign'; observer['resp_body'] = json.dumps(body)
    elif alter == 'redacted':
        observer['capture_redacted'] = True
    elif alter == 'synthetic':
        observer['synthetic'] = True
    elif alter == 'draft':
        observer['status_label'] = 'draft_hypothesis'
    gaps = []
    assert compile_workflow_manifests(captures, diagnostics=gaps) == []
    assert gaps


def test_ambiguous_observers_and_capture_ids_are_blocked(tmp_path):
    _, _, captures, _, _ = prepared(tmp_path)
    observer = next(r for r in captures if r['observed_context']['capture_id'] == 'probe-0')
    duplicate = copy.deepcopy(observer); duplicate['url'] += '/other'
    gaps = []
    assert compile_workflow_manifests(captures + [duplicate], diagnostics=gaps) == []
    assert gaps[0]['reason'] == 'ambiguous_capture_id'


@pytest.mark.parametrize('key', ['expected_rule', 'alternative_explanation', 'evidence_ref',
                                'control', 'probe'])
def test_business_rule_prerequisites(tmp_path, key):
    _, _, captures, _, _ = prepared(tmp_path)
    candidate = next(r for r in captures if r['observed_context'].get('business_rules'))
    candidate['observed_context']['business_rules'][0]['contract'].pop(key)
    assert compile_workflow_manifests(captures) == []


def test_normal_control_must_pass_before_probe(tmp_path):
    prep = prepared(tmp_path)
    lab = prep[0]
    original = lab.sender
    def broken_control(method, url, headers, body, timeout):
        if url == prep[1]['control'] and method == 'POST':
            lab.calls.append((method, url))
            return lab.response(200, {'ok': True})  # Accepted but no legitimate effect.
        return original(method, url, headers, body, timeout)
    lab.sender = broken_control
    result = run_prepared(prep)
    assert result['success'] is False
    assert not any(url == prep[1]['probe'] for _, url in lab.calls)
    assert result['steps_executed'][-1]['oracle_detail']['normal_control_passed'] is False


def test_http_200_never_confirms_business_logic(tmp_path):
    prep = prepared(tmp_path)
    prep[0].sender = lambda *_: LogicLab.response(200, {'ok': True})
    result = run_prepared(prep)
    assert result['success'] is False


@pytest.mark.parametrize('mutation', ['skip_control', 'success_on_failure', 'status_only',
    'wrong_contract', 'wrong_reference', 'extra_step', 'no_identity', 'wrong_phase'])
def test_edited_manifest_cannot_bypass_effect_or_control(tmp_path, mutation):
    prep = prepared(tmp_path)
    m = prep[3]
    if mutation == 'skip_control':
        m['steps'][0]['on_success'] = 'probe-before'
    elif mutation == 'success_on_failure':
        m['steps'][0]['on_failure'] = 'succeed'
    elif mutation == 'status_only':
        m['steps'][-1]['expect'] = {'oracle': 'status_code', 'status': [200]}
    elif mutation == 'wrong_contract':
        m['business_logic']['contract']['session_id'] = 'other'
    elif mutation == 'wrong_reference':
        m['business_logic']['control_before'] = 'probe-before'
    elif mutation == 'extra_step':
        m['steps'].append(copy.deepcopy(m['steps'][-1]))
    elif mutation == 'no_identity':
        m['steps'][1]['identity_refs'] = []
    elif mutation == 'wrong_phase':
        m['steps'][1]['lifecycle_phase'] = 'pre_state'
    result = run_prepared(prep)
    assert result['requests_sent'] == 0 and result['terminal'] == 'invalid_manifest'


def test_legitimate_discount_is_not_replay_evidence(tmp_path):
    prep = prepared(tmp_path, vulnerable=False)
    result = run_prepared(prep)
    detail = result['steps_executed'][-1]['oracle_detail']
    assert detail['normal_control_passed'] is True
    assert detail['violation_effect_observed'] is False
    assert prep[0].objects[prep[1]['probe'].rsplit('/', 1)[-1]]['total'] == 90


@pytest.mark.parametrize('bad', [None, '', '{', '[]', '{"uses": true}', '{"uses": "2"}', '{}'])
def test_invalid_poststate_cannot_confirm(tmp_path, bad):
    prep = prepared(tmp_path)
    result = run_prepared(prep)
    expect = prep[3]['business_logic']
    steps = {s['id']: {**s['result'], 'fulltext': s['result'].get('excerpt', '')}
             for s in result['steps_executed']}
    # Use actual full observations for controls, then replace the probe observation.
    for sid, uses in [('control-before', 0), ('control-after', 1), ('probe-before', 0)]:
        steps[sid] = {'ok': True, 'status': 200, 'fulltext': json.dumps({'uses': uses})}
    steps['probe-after'] = {'ok': True, 'status': 200, 'fulltext': bad}
    assert evaluate_business_logic(expect, steps)[0] is False


def test_status_only_validate_step_cannot_request_confirmation():
    calls = []
    manifest = {'schema_version': 'action-manifest/1.0', 'objective': 'status-only guard',
        'target_ref': 'p7.lab.test', 'risk': 'active_read_only', 'budget': {
            'max_requests': 1, 'max_duration_seconds': 5}, 'identity_refs': [], 'steps': [
        {'id': 'check', 'tool': 'validate', 'args': {'vuln_type': 'business_logic',
             'oracle': 'status_code', 'oracle_args': {'status': [None]}},
         'expect': {'oracle': 'validator_verdict', 'verdict': 'CONFIRMED'},
         'on_success': 'succeed', 'on_failure': 'fail'}]}
    def provider(payload):
        calls.append(payload)
        return {'verdict': payload['verdict']}
    out = ChainExecutor(validate_provider=provider).execute(manifest)
    assert calls[0]['verdict'] == 'UNCONFIRMED'
    assert out['success'] is False


@pytest.mark.parametrize('missing', ['run_id', 'session_id', 'test_account', 'ownership_evidence'])
def test_unbound_seals_are_rejected(tmp_path, missing):
    args = dict(object_url='http://p7.lab.test/objects/a', identity_label='owner',
        task_ref='p7', run_fingerprints=['fp'], run_id='a', session_id='a',
        test_account=True, ownership_evidence={'created': True})
    args.pop(missing)
    with pytest.raises(write_set.WriteSetError):
        write_set.seal_object(str(tmp_path / 'ws.db'), **args)


def test_resealing_cannot_take_over_other_run(tmp_path):
    _, urls, _, _, ctx = prepared(tmp_path)
    with pytest.raises(write_set.WriteSetError, match='cross_run_rejected'):
        write_set.seal_object(ctx['db_path'], object_url=urls['probe'], identity_label='owner',
            task_ref='p7', run_fingerprints=['fp'], run_id='other', session_id='other',
            test_account=True, ownership_evidence={'created': True})
    assert write_set.inspect_object(ctx['db_path'], urls['probe'])['run_id'] == 'run-a'


def test_expiry_and_prestate_are_required(tmp_path):
    _, urls, _, _, ctx = prepared(tmp_path)
    fp = write_set.fingerprint_credentials(IDENTITIES['owner'])
    args = dict(run_id='run-a', session_id='session-a')
    assert not write_set.mutation_permitted(ctx['db_path'], urls['probe'], fp, **args)[0]
    write_set.mark_state(ctx['db_path'], urls['probe'], 'pre_state', evidence={'id': 'a'}, **args)
    row = write_set.inspect_object(ctx['db_path'], urls['probe'])
    assert write_set.mutation_permitted(ctx['db_path'], urls['probe'], fp, **args)[0]
    assert not write_set.mutation_permitted(ctx['db_path'], urls['probe'], fp,
                                          now=row['expires_at'], **args)[0]


def test_query_and_origin_are_part_of_object_identity():
    assert write_set.object_key('http://h/objects?id=a') != write_set.object_key('http://h/objects?id=b')
    assert write_set.object_key('https://h/objects/a') != write_set.object_key('http://h/objects/a')


def test_legacy_seals_fail_closed_after_migration(tmp_path):
    path = str(tmp_path / 'legacy.db')
    conn = sqlite3.connect(path)
    conn.execute('''CREATE TABLE sealed_objects (object_key TEXT PRIMARY KEY, object_url TEXT,
        identity_label TEXT, run_fingerprints TEXT, task_ref TEXT, state TEXT,
        created_at REAL, expires_at REAL)''')
    url = 'http://p7.lab.test/objects/old'
    conn.execute('INSERT INTO sealed_objects VALUES (?,?,?,?,?,?,?,?)',
                 (write_set.object_key(url), url, 'owner', '["fp"]', 'old', 'sealed', 0, 9999999999))
    conn.commit(); conn.close()
    assert not write_set.is_sealed(path, url)
    assert write_set.mutation_permitted(path, url, 'fp', run_id='a', session_id='a') == (False, 'cross_run_rejected')


def test_failed_experiment_still_attempts_fixture_closure(tmp_path):
    class BrokenExecutor:
        def __init__(self, **kwargs):
            pass
        def execute(self, manifest):
            raise RuntimeError('injected transport failure')
    result = write_validate.run_scenario('schema_symmetry', db_path=str(tmp_path / 'ws.db'),
        run_id='a', session_id='a', executor_factory=BrokenExecutor)
    assert 'injected transport failure' in result['terminal_error']
    assert len(result['cleanup']) == 2
    assert all('unknown' in [e['phase'] for e in r['lifecycle']] for r in result['cleanup'])


def test_offline_cli_acceptance(capsys):
    assert write_validate.main(['--offline']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['passed'] is True and len(result['scenarios']) == 10


@pytest.mark.parametrize('bad_flow', [None, [], 'missing', {'actions': [{}]}, {'actions': 'capture-id'}])
def test_malformed_flow_is_an_explicit_gap(tmp_path, bad_flow):
    _, _, captures, _, _ = prepared(tmp_path)
    candidate = next(r for r in captures if r['observed_context'].get('business_rules'))
    candidate['observed_context']['business_rules'][0]['control'] = bad_flow
    gaps = []
    assert compile_workflow_manifests(captures, diagnostics=gaps) == []
    assert gaps and gaps[-1]['status'] == 'missing_prerequisite'


def test_normal_effect_must_be_present_in_capture(tmp_path):
    _, _, captures, _, _ = prepared(tmp_path)
    after = next(r for r in captures if r['observed_context']['capture_id'] == 'control-2')
    body = json.loads(after['resp_body']); body['uses'] = 0; after['resp_body'] = json.dumps(body)
    gaps = []
    assert compile_workflow_manifests(captures, diagnostics=gaps) == []
    assert any(g['reason'] == 'unobserved_normal_effect' for g in gaps)


def test_wrong_runtime_observer_identity_aborts(tmp_path):
    prep = prepared(tmp_path)
    lab = prep[0]; original = lab.sender
    def wrong_identity(method, url, headers, body, timeout):
        resp = original(method, url, headers, body, timeout)
        if method == 'GET':
            data = json.loads(resp['text']); data['id'] = 'different-object'
            return lab.response(200, data)
        return resp
    lab.sender = wrong_identity
    result = run_prepared(prep)
    assert not result['success']
    assert result['requests_sent'] == 1
    assert 'resource identity mismatch' in result['terminal_error']


def test_rejected_seal_never_triggers_other_runs_teardown(tmp_path):
    prep = prepared(tmp_path)
    lab = prep[0]
    foreign = prep[1]['probe']
    lab.setup = lambda *_: foreign
    closed = []
    lab.close = lambda url: closed.append(url)
    result = write_validate.run_scenario('idempotency_replay', db_path=prep[-1]['db_path'],
        run_id='other-run', session_id='other-session', lab=lab)
    assert 'cross_run_rejected' in result['terminal_error']
    assert closed == [] and result['unresolved_fixtures'] == [foreign]
    assert write_set.inspect_object(prep[-1]['db_path'], foreign)['state'] == 'sealed'


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf')])
def test_nonfinite_seal_time_is_rejected(tmp_path, value):
    with pytest.raises(write_set.WriteSetError, match='finite'):
        write_set.seal_object(str(tmp_path / 'ws.db'), object_url='http://p7.lab.test/objects/a',
            identity_label='owner', task_ref='p7', run_fingerprints=['fp'],
            run_id='a', session_id='a', test_account=True, ownership_evidence={'created': True}, now=value)


def test_unscoped_unknown_object_and_missing_identity_send_nothing(tmp_path):
    prep = prepared(tmp_path)
    runner = ChainExecutor(policy_engine=AllowGate(), sender=prep[0].sender,
        identities={}, write_context=prep[-1])
    result = runner.execute(prep[3])
    assert not result['success'] and result['requests_sent'] == 0
    assert not prep[0].calls


def test_wire_gate_denial_does_not_mutate_fixture(tmp_path):
    prep = prepared(tmp_path)
    class DenyGate:
        def validate_tool_invocation(self, *_args, **_kwargs):
            return {'allowed': False, 'reason': 'scope denied'}
    result = ChainExecutor(policy_engine=DenyGate(), sender=prep[0].sender,
        identities=IDENTITIES, write_context=prep[-1]).execute(prep[3])
    assert result['requests_sent'] == 0 and not result['success']
    assert not prep[0].calls


@pytest.mark.parametrize('vuln_type', ['business_logic', 'BUSINESS_LOGIC', 'Business Logic',
                                    'price-manipulation', 'mass_assignment'])
def test_business_logic_default_provider_demotes_status_only(monkeypatch, vuln_type):
    import chain_executor
    calls = []
    class Validator:
        def _result(self, *args, **kwargs):
            calls.append(args)
            return json.dumps({'verdict': args[2]})
    monkeypatch.setattr(chain_executor, '_lazy_server', lambda name: Validator())
    out = chain_executor.default_validate_provider({'vuln_type': vuln_type,
        'verdict': 'CONFIRMED', 'oracle': 'status_code', 'evidence': {'status': 200}})
    assert out['verdict'] == 'UNCONFIRMED' and calls[0][2] == 'UNCONFIRMED'


def test_testplan_generated_draft_is_not_runnable():
    from conftest import load_server
    load_server('hunter')
    from cco_hunter_core.testplan import plan_from_hypothesis, execute_test_plan
    endpoint = {'path': '/checkout', 'params': [{'name': 'quantity'}],
                'synthetic': True, 'mutation': -1,
                'request_context': {'method': 'POST', 'url': 'https://example.test/checkout',
                                    'body': {'quantity': 1}}}
    plan = plan_from_hypothesis(endpoint, 'business_logic')
    assert plan['hypothesis']['status'] == 'draft_hypothesis'
    assert plan['experiment']['status'] == 'blocked'
    calls = []
    result = execute_test_plan(plan, lambda req: calls.append(req))
    assert result['requests_executed'] == 0 and calls == []


def bound_p7(tmp_path, monkeypatch, vulnerable=True):
    from evidence_chaining import EvidenceGraph, digest, origin
    from python_workflow_fixtures import workflow_engine
    prep = prepared(tmp_path, vulnerable=vulnerable)
    lab, urls, captures, manifest, write_context = prep
    context = {'origin': origin(urls['probe']), 'tenant': 'synthetic-tenant',
               'run_id': write_context['run_id'], 'session_id': write_context['session_id']}
    clock = [1000.0]
    graph = EvidenceGraph(tmp_path / 'evidence.db', clock=lambda: clock[0])
    def observe(kind, **values):
        return graph.observe({'kind': kind, 'context': context, 'observed_at': 1000.0,
                              'expires_at': 2000.0, **values})
    identity_hashes = {name: observe('identity', identity_ref=name, credential_hash=digest(headers),
        actor={'test_data_only': True, 'identity_facts': [
            {'field': field, 'value': value, 'source': 'operator', 'evidence': 'E4 fixture'}
            for field, value in {'principal': name, 'tenant': context['tenant'], 'authority': 'p7.lab.test'}.items()]})
        for name, headers in IDENTITIES.items() if name in manifest['identity_refs']}
    identities = {name: IDENTITIES[name] for name in identity_hashes}
    source_hashes = [observe('exchange', capture=capture, identity_ref=capture['observed_context']['identity_ref'],
        credential_hash=digest(IDENTITIES[capture['observed_context']['identity_ref']]),
        request={'url': capture['url'], 'method': capture['method'], 'body': capture['req_body']},
        response={'ok': True, 'status': capture['status'], 'body': json.loads(capture['resp_body'])})
        for capture in captures]
    resource_hashes = {url: observe('resource', resource={
        'url': url, 'resource_id': url.rsplit('/', 1)[-1], 'owner_identity': 'owner',
        'test_data_only': True, 'tenant': context['tenant']}) for url in urls.values()}
    permission_hash = observe('permission', scope_allowed=True, read_allowed=True,
                              write_allowed=True, urls=sorted(urls.values()))
    runtime = {**context, 'program_id': 'e4-local', 'identity_hashes': identity_hashes,
               'resource_hashes': resource_hashes, 'permission_hash': permission_hash}
    broker, spec = workflow_engine(tmp_path, monkeypatch, 'http://p7.lab.test', identities, lab.sender)
    ref = broker.bind_workflow(spec.id, manifest, graph=graph, runtime=runtime, identities=identities,
        capture_hashes=source_hashes, authorized_tools=['chain_runner_http_get', 'chain_runner_http_post'],
        write_context=write_context)
    return broker, spec, ref, graph, clock, prep


@pytest.mark.parametrize('vulnerable', [True, False])
def test_p7_python_phase_compiled_manifest_signed_evidence(tmp_path, monkeypatch, vulnerable):
    from evidence_trust import canonical_bytes, verify
    from python_workflow_binding import EVIDENCE_PURPOSE
    from python_workflow_fixtures import run_workflow_phase
    broker, spec, ref, graph, _, prep = bound_p7(tmp_path, monkeypatch, vulnerable)
    try:
        _, summary, prompts = run_workflow_phase(broker, spec, ref, monkeypatch)
        value = json.loads((broker.workdir / broker.results[0]['content_ref']['path']).read_bytes())
        signed = value['signed_evidence']
        assert verify(canonical_bytes(signed['payload']), signed, EVIDENCE_PURPOSE)
        result = signed['payload']['result']
        assert result['verdict'] == ('CONFIRMED' if vulnerable else 'NOT_CONFIRMED')
        assert result['requests_sent'] == len(prep[3]['steps']) == len(prep[0].calls)
        assert broker.budget.used['http'] == result['requests_sent']
        assert summary['compiled_workflows'][0]['status'] == 'TESTED'
        assert summary['findings'] == [] and value['reportable'] is False
        schema = next(t['function']['parameters'] for t in prompts[0]['tools']
                      if t['function']['name'] == 'workflow_execute_compiled')
        assert schema['additionalProperties'] is False
        assert schema['properties'] == {'binding_ref': {'type': 'string', 'enum': [ref]}}
        signed['payload']['result']['verdict'] = 'forged'
        assert not verify(canonical_bytes(signed['payload']), signed, EVIDENCE_PURPOSE)
    finally:
        graph.close()


@pytest.mark.parametrize('failure', ['missing', 'tampered', 'invalidated', 'expired', 'program',
                                   'manifest', 'identity', 'object_owner', 'object_run', 'object_expired', 'task'])
def test_p7_python_binding_fail_closed_zero_requests(tmp_path, monkeypatch, failure):
    broker, spec, ref, graph, clock, prep = bound_p7(tmp_path, monkeypatch)
    binding = broker.workflow_bindings[ref]
    try:
        h = binding.capture_hashes[-1]
        if failure == 'missing':
            graph.db.execute('DELETE FROM p8_evidence WHERE hash=?', (h,))
        elif failure == 'tampered':
            graph.db.execute("UPDATE p8_evidence SET payload='{}' WHERE hash=?", (h,))
        elif failure == 'invalidated':
            graph.invalidate(h)
        elif failure == 'expired':
            clock[0] = 2000.0
        elif failure == 'program':
            broker.engine.program_policy_file.write_text('{"profile":"another-program"}')
            broker.engine.reload(force=True)
        elif failure == 'manifest':
            binding.manifest['steps'][1]['args']['body']['op'] = 'unobserved'
        elif failure == 'identity':
            binding.identities['owner'] = IDENTITIES['other']
        elif failure.startswith('object'):
            conn = sqlite3.connect(prep[-1]['db_path'])
            field, value = {'object_owner': ('identity_label', 'foreign-owner'),
                            'object_run': ('run_id', 'other-run'), 'object_expired': ('expires_at', 0)}[failure]
            conn.execute(f'UPDATE sealed_objects SET {field}=?', (value,))
            conn.commit(); conn.close()
        elif failure == 'task':
            spec.target = 'http://another-program.test'
        from orchestration_spec import COMPILED_WORKFLOW_TOOL
        result = broker.invoke(COMPILED_WORKFLOW_TOOL, {'binding_ref': ref})['result']
        assert result['execution_failed'] and result['requests_sent'] == 0
        assert prep[0].calls == [] and broker.budget.used['http'] == 0
    finally:
        graph.close()


@pytest.mark.parametrize('failure', ['expired', 'invalidated'])
def test_p7_expiry_between_observer_and_mutation_sends_no_write(tmp_path, monkeypatch, failure):
    broker, spec, ref, graph, clock, prep = bound_p7(tmp_path, monkeypatch)
    original = broker.workflow_sender
    def sender(*args):
        result = original(*args)
        if failure == 'expired':
            clock[0] = 2000.0
        else:
            graph.invalidate(broker.workflow_bindings[ref].capture_hashes[-1])
        return result
    broker.workflow_sender = sender
    try:
        value = broker.invoke('workflow_execute_compiled', {'binding_ref': ref})['result']
        assert value['execution_failed'] and value['requests_sent'] == 1
        assert prep[0].calls == [('GET', prep[1]['control'])]
        assert broker.budget.used['http'] == 1
    finally:
        graph.close()


@pytest.mark.parametrize('tools', [[], ['chain_runner_http_get'], ['chain_runner_http_get', 'chain_runner_http_post', 'chain_runner_race_burst']])
def test_p7_binding_requires_explicit_exact_step_tool_authorization(tmp_path, monkeypatch, tools):
    broker, spec, _, graph, _, _ = bound_p7(tmp_path, monkeypatch)
    binding = next(iter(broker.workflow_bindings.values()))
    try:
        with pytest.raises(ValueError, match='workflow_tool_authorization_denied'):
            broker.bind_workflow(spec.id, binding.manifest, graph=graph, runtime=binding.runtime,
                identities=binding.identities, capture_hashes=binding.capture_hashes,
                write_context=binding.write_context, authorized_tools=tools)
    finally:
        graph.close()
