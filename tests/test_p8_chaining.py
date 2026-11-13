"""P8 socket-free chaining, adversarial contexts, safe twins and durable replay."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from action_manifest import validate_manifest
from chain_executor import ChainExecutor
from evidence_chaining import EvidenceError, EvidenceGraph, RELATIONS, digest, origin
from workflow_compiler import compile_evidence_chain
from conftest import load_server

URL = 'https://p8.test/api/invoices/invoice-a'
NEGATIVE = 'https://p8.test/api/invoices/missing-test-object'
PRODUCER = 'https://p8.test/api/orders/order-a'
CONTEXT = {'origin': origin(URL), 'tenant': 'tenant-a', 'run_id': 'run-p8', 'session_id': 'session-p8'}


def bound_p8(s, tmp_path, monkeypatch):
    from python_workflow_fixtures import workflow_engine
    broker, task = workflow_engine(tmp_path, monkeypatch, 'https://p8.test', s['identities'], s['lab'].sender)
    runtime = {**s['runtime'], 'program_id': 'e4-local', 'identity_hashes': s['spec']['identity_hashes'],
               'permission_hash': s['spec']['permission_hash'], 'resource_hashes': {URL: s['spec']['resource_hash']}}
    ref = broker.bind_workflow(task.id, compile_evidence_chain(s['graph'], s['spec'])['manifest'],
        graph=s['graph'], runtime=runtime, identities=s['identities'], authorized_tools=['chain_runner_http_get'])
    return broker, task, ref


@pytest.mark.parametrize('failure', ['missing', 'tampered', 'expired', 'identity', 'tenant', 'program', 'permission', 'signature'])
def test_p8_python_binding_zero_downstream_requests(setup, tmp_path, monkeypatch, failure):
    s = setup
    broker, task, ref = bound_p8(s, tmp_path, monkeypatch)
    binding = broker.workflow_bindings[ref]
    if failure == 'missing':
        s['graph'].db.execute('DELETE FROM p8_evidence WHERE hash=?', (s['spec']['captures']['negative'],))
    elif failure == 'tampered':
        s['graph'].db.execute("UPDATE p8_evidence SET payload='{}' WHERE hash=?", (s['spec']['permission_hash'],))
    elif failure == 'expired':
        s['clock'][0] = 2000.0
    elif failure == 'identity':
        binding.identities['bob'] = binding.identities['alice']
    elif failure == 'tenant':
        binding.runtime['tenant'] = 'tenant-b'
    elif failure == 'program':
        broker.engine.program_policy_file.write_text('{"profile":"another-program"}')
        broker.engine.reload(force=True)
    elif failure == 'permission':
        broker.engine.program_policy_file.write_text(json.dumps({'profile': 'e4-local',
                                                               'denied_tools': ['chain_runner_http_get']}))
    elif failure == 'signature':
        task.compiled_workflows[ref]['signature'] = '00' * 64
    result = broker.invoke('workflow_execute_compiled', {'binding_ref': ref})['result']
    assert result['requests_sent'] == 0 and result['success'] is False
    assert s['lab'].calls == [] and broker.budget.used['http'] == 0


@pytest.mark.parametrize('args', [{'manifest': {}}, {'binding_ref': 'unregistered'},
    {'binding_ref': 'REF', 'url': 'https://p8.test/unobserved'}, {'binding_ref': 'REF', 'authorized_tools': ['chain_runner_http_post']}])
def test_model_cannot_supply_http_chains_or_widen_binding(setup, tmp_path, monkeypatch, args):
    broker, task, ref = bound_p8(setup, tmp_path, monkeypatch)
    args = {k: ref if v == 'REF' else v for k, v in args.items()}
    with pytest.raises(ValueError):
        broker.invoke('workflow_execute_compiled', args)
    assert not setup['lab'].calls and broker.budget.used['http'] == 0


def test_compiled_task_cannot_bypass_sources_with_raw_http(setup, tmp_path, monkeypatch):
    from full_agent_python_solver import PythonSolver
    broker, task, ref = bound_p8(setup, tmp_path, monkeypatch)
    task.tools.extend(['kali-tools_curl_request', 'hunter_run_web_loop'])
    broker.catalog = {'kali-tools': [{'name': 'curl_request', 'inputSchema': {'type': 'object'}}]}
    solver = PythonSolver(broker, model='local')
    assert task.id not in broker.runtime_policy.validation_reserves
    assert not solver.dispatch_access_validation(task)
    assert 'kali-tools_curl_request' not in {t['function']['name'] for t in solver.tool_schemas(task)}
    setup['clock'][0] = 2000.0
    with pytest.raises(ValueError):
        broker.invoke('kali-tools_curl_request', {'url': URL, 'method': 'POST', 'body': 'unconstrained'})
    assert not setup['lab'].calls and broker.budget.used['http'] == 0


@pytest.mark.parametrize('safe', [True, False])
def test_p8_python_loopback_phase_and_signed_replay(setup, tmp_path, monkeypatch, safe):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    from urllib.parse import urlsplit
    from evidence_trust import canonical_bytes, verify
    from python_workflow_binding import EVIDENCE_PURPOSE
    from python_workflow_fixtures import workflow_engine, run_workflow_phase
    lab = ReadLab(safe=safe)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            mapped = 'https://p8.test' + self.path
            result = lab.sender('GET', mapped, dict(self.headers), '', 15)
            raw = result['text'].encode()
            self.send_response(result['status'])
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f'http://127.0.0.1:{server.server_port}'
    ctx = {**CONTEXT, 'origin': origin(base_url)}
    graph = EvidenceGraph(tmp_path / 'loopback.db', clock=setup['graph'].clock)
    try:
        def rebase(url):
            return base_url + urlsplit(url).path
        spec = copy.deepcopy(setup['spec'])
        spec['context'] = ctx
        old_hashes = [spec['resource_hash'], spec['permission_hash'],
                      *spec['identity_hashes'].values(), *spec['captures'].values()]
        replacements = {}
        for h in old_hashes:
            record = setup['graph'].evidence(h)
            record['context'] = ctx
            if 'request' in record:
                record['request']['url'] = rebase(record['request']['url'])
            if 'resource' in record:
                record['resource']['url'] = rebase(record['resource']['url'])
            if 'urls' in record:
                record['urls'] = sorted(rebase(url) for url in record['urls'])
            replacements[h] = graph.observe(record)
        for key in ('resource_hash', 'permission_hash'):
            spec[key] = replacements[spec[key]]
        for key in ('identity_hashes', 'captures'):
            spec[key] = {name: replacements[h] for name, h in spec[key].items()}
        runtime = {**ctx, 'program_id': 'e4-local', 'scope_allowed': True, 'read_allowed': True,
                   'resource_hash': spec['resource_hash'], 'resource_hashes': {rebase(URL): spec['resource_hash']},
                   'permission_hash': spec['permission_hash'], 'identity_hashes': spec['identity_hashes']}
        broker, task = workflow_engine(tmp_path, monkeypatch, base_url, setup['identities'])
        ref = broker.bind_workflow(task.id, compile_evidence_chain(graph, spec)['manifest'], graph=graph,
            runtime=runtime, identities=setup['identities'], authorized_tools=['chain_runner_http_get'])
        solver, summary, prompts = run_workflow_phase(broker, task, ref, monkeypatch)
        value = json.loads((broker.workdir / broker.results[0]['content_ref']['path']).read_bytes())
        signed = value['signed_evidence']
        assert verify(canonical_bytes(signed['payload']), signed, EVIDENCE_PURPOSE)
        result = signed['payload']['result']
        assert result['requests_sent'] == len(lab.calls) == broker.budget.used['http'] == 4
        assert result['verdict'] == ('NOT_CONFIRMED' if safe else 'CONFIRMED')
        assert graph.replay(result['replay_evidence_hash'])['verdict'] == result['verdict']
        assert summary['compiled_workflows'][0]['status'] == 'TESTED' and not summary['findings']
        prompt = json.dumps(prompts)
        assert 'synthetic=alice' not in prompt and 'synthetic=bob' not in prompt
        graph.invalidate(spec['captures']['owner'])
        assert broker.verified_workflow_executions(task)[0]['status'] == 'NOT TESTED'
    finally:
        graph.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

def actor(principal):
    return {'test_data_only': True, 'identity_facts': [
        {'field': field, 'value': value, 'source': 'operator', 'evidence': 'fixture:accounts'}
        for field, value in {'principal': principal, 'tenant': 'tenant-a', 'authority': 'p8.test', 'role': 'member'}.items()]}


class ReadLab:
    """Actual in-memory handler calls; every account/object is synthetic."""
    def __init__(self, safe=False):
        self.safe = safe
        self.calls = []
        self.private = {'id': 'invoice-a', 'private_marker': 'synthetic-owned-invoice-line'}

    def sender(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers.get('Cookie')))
        identity = headers.get('Cookie')
        if method != 'GET' or identity not in {'synthetic=alice', 'synthetic=bob'}:
            status, payload = 403, {'error': 'denied'}
        elif url == PRODUCER and identity == 'synthetic=alice':
            status, payload = 200, {'id': 'order-a', 'invoice_id': 'invoice-a'}
        elif url == URL and (identity == 'synthetic=alice' or not self.safe):
            status, payload = 200, self.private
        elif url == URL:
            status, payload = 403, {'error': 'private'}
        else:
            status, payload = 404, {'error': 'missing'}
        return {'ok': True, 'status': status, 'text': json.dumps(payload), 'headers': {}, 'location': ''}


class Gate:
    def __init__(self, denied=None):
        self.calls = []
        self.denied = denied

    def validate_tool_invocation(self, tool, args):
        self.calls.append((tool, args['url']))
        return {'allowed': args['url'] in {URL, NEGATIVE, PRODUCER} and args['url'] != self.denied,
                'reason': 'fixture scope denied'}


@pytest.fixture
def setup(tmp_path):
    clock = [1000.0]
    graph = EvidenceGraph(tmp_path / 'agent_memory.db', clock=lambda: clock[0])
    identities = {'alice': {'Cookie': 'synthetic=alice'}, 'bob': {'Cookie': 'synthetic=bob'}}
    lab = ReadLab()

    def base(kind, **kw):
        return {'kind': kind, 'context': copy.deepcopy(CONTEXT), 'observed_at': 1000.0,
                'expires_at': 2000.0, **kw}

    identity_hashes = {name: graph.observe(base('identity', identity_ref=name,
                       actor=actor(name), credential_hash=digest(headers))) for name, headers in identities.items()}
    resource_hash = graph.observe(base('resource', resource={
        'resource_id': 'invoice-a', 'url': URL, 'family': 'invoices', 'tenant': 'tenant-a', 'owner_identity': 'alice',
        'test_data_only': True, 'access_rule': {'visibility': 'private', 'owner_only': True,
        'authentication_required': True, 'source': 'operator', 'evidence': 'fixture:private-policy'}}))
    permission_hash = graph.observe(base('permission', scope_allowed=True, read_allowed=True,
                                        urls=sorted({URL, NEGATIVE, PRODUCER})))
    captures = {}
    for role, name, url in [('producer', 'alice', PRODUCER), ('owner', 'alice', URL),
                            ('negative', 'bob', NEGATIVE), ('peer', 'bob', URL)]:
        result = lab.sender('GET', url, identities[name], '', 15)
        captures[role] = graph.observe(base('exchange', identity_ref=name,
            credential_hash=digest(identities[name]), request={'url': url, 'method': 'GET', 'body': ''},
            response={'ok': result['ok'], 'status': result['status'], 'body': json.loads(result['text'])}))
    spec = {'context': copy.deepcopy(CONTEXT), 'resource_hash': resource_hash, 'permission_hash': permission_hash,
            'identity_hashes': identity_hashes, 'owner_identity': 'alice', 'peer_identity': 'bob',
            'captures': captures, 'response_field': 'invoice_id', 'request_field': 'path.3',
            'value_type': 'string', 'resource_field': 'id', 'private_field': 'private_marker'}
    runtime = {**CONTEXT, 'scope_allowed': True, 'read_allowed': True, 'resource_hash': resource_hash}
    lab.calls.clear()
    yield {'graph': graph, 'clock': clock, 'lab': lab, 'spec': spec, 'identities': identities, 'runtime': runtime, 'base': base}
    graph.close()


def executor(s, lab=None, gate=None, runtime=None, identities=None):
    return ChainExecutor(policy_engine=gate or Gate(), sender=(lab or s['lab']).sender,
        identities=s['identities'] if identities is None else identities, evidence_graph=s['graph'],
        evidence_context=s['runtime'] if runtime is None else runtime,
        validate_provider=lambda *_: pytest.fail('P8 called provider'),
        finding_store=lambda *_: pytest.fail('P8 stored unsigned finding'))


def change_evidence(s, key, mutation):
    spec = copy.deepcopy(s['spec'])
    container = spec['captures'] if key in spec['captures'] else spec['identity_hashes'] if key in spec['identity_hashes'] else spec
    h = container[key]
    data = s['graph'].evidence(h)
    mutation(data)
    container[key] = s['graph'].observe(data)
    return spec


@pytest.mark.parametrize('safe', [False, True])
def test_real_handler_twins_and_deterministic_replay(setup, safe):
    s = setup
    compiled = compile_evidence_chain(s['graph'], s['spec'])
    assert compiled['status'] == 'ready' and compiled['severity'] is None
    lab, gate = ReadLab(safe=safe), Gate()
    result = executor(s, lab=lab, gate=gate).execute(compiled['manifest'])
    assert result['requests_sent'] == len(lab.calls) == len(gate.calls) == 4
    assert result['verdict'] == ('NOT_CONFIRMED' if safe else 'CONFIRMED')
    assert result['success'] is (not safe)
    assert result['effect']['negative_control_passed'] is True
    assert result['effect']['violation_effect_observed'] is (not safe)
    replay = s['graph'].replay(result['replay_evidence_hash'])
    assert replay['verdict'] == result['verdict'] and replay['effect'] == result['effect']
    assert not replay['reportable'] and not result['reportable']
    kinds = [json.loads(r[0])['kind'] for r in s['graph'].db.execute('SELECT payload FROM p8_relations')]
    assert ('validated_effect' in kinds) is (not safe)


@pytest.mark.parametrize('field,value', [('tenant', 'tenant-b'), ('run_id', 'other-run'),
    ('session_id', 'other-session'), ('origin', 'https://other.test:443')])
def test_context_mismatch_blocks_only_chain(setup, field, value):
    spec = change_evidence(setup, 'peer', lambda d: d['context'].update({field: value})) if field != 'origin' else copy.deepcopy(setup['spec'])
    if field == 'origin':
        spec['context'][field] = value
    result = compile_evidence_chain(setup['graph'], spec)
    assert result['status'] == 'blocked' and not result['runnable']
    assert compile_evidence_chain(setup['graph'], setup['spec'])['runnable']


@pytest.mark.parametrize('field', ['tenant', 'run_id', 'session_id', 'origin', 'resource_hash', 'scope_allowed', 'read_allowed'])
def test_trusted_runtime_mismatches_send_nothing(setup, field):
    manifest = setup['graph'].build_plan(setup['spec'])
    runtime = dict(setup['runtime'])
    runtime[field] = False if field.endswith('allowed') else 'wrong'
    result = executor(setup, runtime=runtime).execute(manifest)
    assert result['terminal'] == 'not_runnable' and result['requests_sent'] == 0
    assert not setup['lab'].calls


@pytest.mark.parametrize('change', ['reference', 'type', 'missing', 'identity', 'credential', 'same_principal',
                                  'tenant', 'test_data', 'public', 'shared', 'no_rule', 'scope', 'permission', 'permission_urls'])
def test_unvalidated_prerequisites_are_never_chains(setup, change):
    s, spec = setup, copy.deepcopy(setup['spec'])
    if change in {'reference', 'type', 'missing'}:
        def mutate(d):
            if change == 'missing':
                d['response']['body'].pop('invoice_id')
            else:
                d['response']['body']['invoice_id'] = 1 if change == 'type' else 'invoice-unrelated'
        spec = change_evidence(s, 'producer', mutate)
    elif change in {'identity', 'credential'}:
        spec = change_evidence(s, 'peer', lambda d: d.update({
            'identity_ref' if change == 'identity' else 'credential_hash': 'alice' if change == 'identity' else 'wrong'}))
    elif change == 'same_principal':
        spec = change_evidence(s, 'bob', lambda d: d.update(actor=actor('alice')))
    elif change in {'tenant', 'test_data', 'public', 'shared', 'no_rule'}:
        def mutate(d):
            r = d['resource']
            if change == 'tenant': r['tenant'] = 'tenant-b'
            elif change == 'test_data': r['test_data_only'] = False
            elif change == 'no_rule': r['access_rule'] = {}
            else: r['access_rule']['visibility'] = change
        spec = change_evidence(s, 'resource_hash', mutate)
    else:
        spec = change_evidence(s, 'permission_hash', lambda d: d.update({
            {'scope': 'scope_allowed', 'permission': 'read_allowed', 'permission_urls': 'urls'}[change]:
            [] if change == 'permission_urls' else False}))
    result = compile_evidence_chain(s['graph'], spec)
    assert result['status'] == 'blocked' and result['edge_status'] == 'unvalidated_edge'
    assert result['severity'] is None


def test_two_correct_observations_without_exact_link_never_confirm(setup):
    spec = change_evidence(setup, 'producer', lambda d: d['response']['body'].update(invoice_id='invoice-b'))
    result = compile_evidence_chain(setup['graph'], spec)
    assert not result['runnable'] and result['verdict'] == 'INCONCLUSIVE'


@pytest.mark.parametrize('edit', ['oracle', 'skip', 'requires', 'url', 'binding', 'relation', 'effect', 'budget', 'identity'])
def test_edited_manifests_fail_before_any_request(setup, edit):
    manifest = setup['graph'].build_plan(setup['spec'])
    if edit == 'oracle': manifest['steps'][-1]['expect'] = {'oracle': 'status_code', 'status': 200}
    elif edit == 'skip': manifest['steps'][0]['on_success'] = 'peer'
    elif edit == 'requires': manifest['steps'][-1]['requires'] = []
    elif edit == 'url': manifest['steps'][-1]['args']['url'] = NEGATIVE
    elif edit == 'binding': manifest['evidence_chain']['bindings'][0]['value'] = 'invoice-b'
    elif edit == 'relation': manifest['evidence_chain']['relation_ids'] = ['invented-edge']
    elif edit == 'effect': manifest['evidence_chain']['effect']['oracle'] = 'status_code'
    elif edit == 'identity': manifest['steps'][-1]['identity_refs'] = ['alice']
    else: manifest['budget']['max_requests'] = 100
    result = executor(setup).execute(manifest)
    assert result['requests_sent'] == 0 and result.get('verdict') != 'CONFIRMED'
    assert not setup['lab'].calls


@pytest.mark.parametrize('target', ['alice', 'bob'])
def test_rotated_or_swapped_actual_credentials_require_rebind(setup, target):
    identities = copy.deepcopy(setup['identities'])
    identities[target] = {'Cookie': 'synthetic=rotated'}
    manifest = setup['graph'].build_plan(setup['spec'])
    assert executor(setup, identities=identities).execute(manifest)['requests_sent'] == 0


@pytest.mark.parametrize('role', ['producer', 'owner', 'negative', 'peer'])
def test_wire_scope_denial_stops_chain_and_is_visible(setup, role):
    manifest = setup['graph'].build_plan(setup['spec'])
    denied = manifest['steps'][['producer', 'owner', 'negative', 'peer'].index(role)]['args']['url']
    result = executor(setup, gate=Gate(denied=denied)).execute(manifest)
    assert result['verdict'] == 'INCONCLUSIVE' and not result['success']
    assert result['requests_sent'] < 4


@pytest.mark.parametrize('change', ['reference', '200_only', 'wrong_resource', 'wrong_marker', 'negative_200', 'negative_leak', 'malformed', 'transport'])
def test_runtime_counterexamples_cannot_confirm(setup, change):
    lab = ReadLab()
    send = lab.sender
    def sender(method, url, headers, body, timeout):
        result = send(method, url, headers, body, timeout)
        if change == 'reference' and url == PRODUCER: result['text'] = json.dumps({'invoice_id': 'new-invoice'})
        if url == URL and headers.get('Cookie') == 'synthetic=bob':
            if change == '200_only': result['text'] = '{}'
            elif change == 'wrong_resource': result['text'] = json.dumps({**lab.private, 'id': 'invoice-b'})
            elif change == 'wrong_marker': result['text'] = json.dumps({**lab.private, 'private_marker': 'unrelated'})
            elif change == 'malformed': result['text'] = '<error>'
            elif change == 'transport': result['ok'] = False
        if url == NEGATIVE and change in {'negative_200', 'negative_leak'}:
            result['status'] = 200 if change == 'negative_200' else 404
            result['text'] = json.dumps(lab.private)
        return result
    lab.sender = sender
    manifest = setup['graph'].build_plan(setup['spec'])
    result = executor(setup, lab=lab).execute(manifest)
    assert not result['success'] and result['verdict'] != 'CONFIRMED'
    assert result['requests_sent'] < 4 if change in {'reference', 'negative_200', 'negative_leak'} else result['requests_sent'] == 4


@pytest.mark.parametrize('expired', [False, True])
def test_all_dependent_jobs_invalidated_and_unrelated_jobs_preserved(setup, expired):
    g, spec = setup['graph'], setup['spec']
    assert g.register_job('chain-1', spec)['status'] == 'ready'
    assert g.register_job('chain-2', spec)['status'] == 'ready'
    with g.db:
        g.db.execute("INSERT INTO p8_chain_jobs VALUES ('unrelated','{}','null','blocked','scope_denied')")
    if expired: setup['clock'][0] = 2001
    else: g.invalidate(spec['captures']['producer'])
    assert g.job('chain-1')['status'] == g.job('chain-2')['status'] == 'invalidated'
    assert g.job('unrelated')['reason'] == 'scope_denied'


@pytest.mark.parametrize('prerequisite', ['resource_hash', 'permission_hash', 'negative', 'bob'])
def test_nonflow_prerequisites_also_invalidate_jobs(setup, prerequisite):
    g, spec = setup['graph'], setup['spec']
    g.register_job('chain', spec)
    h = spec['captures'].get(prerequisite) or spec['identity_hashes'].get(prerequisite) or spec[prerequisite]
    g.invalidate(h)
    assert g.job('chain')['status'] == 'invalidated'


def test_observed_reference_retriggers_only_waiting_hypothesis(setup):
    g, spec = setup['graph'], copy.deepcopy(setup['spec'])
    fresh = g.evidence(spec['captures']['producer'])
    fresh['capture_id'] = 'delivered-source-observation'
    spec['captures']['producer'] = digest(fresh)
    assert g.register_job('waiting', spec)['status'] == 'blocked'
    g.register_job('ready', setup['spec'])
    g.observe(fresh)
    assert g.job('waiting')['status'] == g.job('ready')['status'] == 'ready'


def test_later_producer_does_not_prove_an_earlier_consumption(setup):
    g = setup['graph']
    setup['clock'][0] = 1001
    fresh = g.evidence(setup['spec']['captures']['producer'])
    fresh['observed_at'] = 1001
    spec = copy.deepcopy(setup['spec'])
    spec['captures']['producer'] = g.observe(fresh)
    result = compile_evidence_chain(g, spec)
    assert not result['runnable'] and result['reason'] == 'reference_not_yet_observed'


def test_refresh_after_expiry_needs_new_source_proofs(setup):
    g, spec = setup['graph'], setup['spec']
    g.register_job('chain', spec)
    setup['clock'][0] = 2001.0
    assert g.job('chain')['status'] == 'invalidated'
    fresh = copy.deepcopy(spec)
    hashes = [spec['resource_hash'], spec['permission_hash'], *spec['captures'].values(), *spec['identity_hashes'].values()]
    replacements = {}
    for h in hashes:
        d = json.loads(g.db.execute('SELECT payload FROM p8_evidence WHERE hash=?', (h,)).fetchone()[0])
        d.update(observed_at=2001.0, expires_at=3000.0)
        replacements[h] = g.observe(d)
    fresh['resource_hash'], fresh['permission_hash'] = replacements[spec['resource_hash']], replacements[spec['permission_hash']]
    fresh['captures'] = {k: replacements[h] for k, h in spec['captures'].items()}
    fresh['identity_hashes'] = {k: replacements[h] for k, h in spec['identity_hashes'].items()}
    assert g.register_job('chain', fresh)['status'] == 'ready'


@pytest.mark.parametrize('tamper', ['evidence', 'relation', 'replay'])
def test_hash_tampering_fails_closed(setup, tamper):
    g, manifest = setup['graph'], setup['graph'].build_plan(setup['spec'])
    result = executor(setup).execute(manifest)
    if tamper == 'relation':
        table, key, value = 'p8_relations', 'id', manifest['evidence_chain']['relation_ids'][0]
    else:
        table, key = 'p8_evidence', 'hash'
        value = result['replay_evidence_hash'] if tamper == 'replay' else setup['spec']['captures']['producer']
    row = g.db.execute(f'SELECT payload FROM {table} WHERE {key}=?', (value,)).fetchone()
    data = json.loads(row[0]); data['tampered'] = True
    with g.db: g.db.execute(f'UPDATE {table} SET payload=? WHERE {key}=?', (json.dumps(data), value))
    with pytest.raises(EvidenceError): g.replay(result['replay_evidence_hash'])


def test_durable_replay_after_reopening_store(setup, tmp_path):
    result = executor(setup).execute(setup['graph'].build_plan(setup['spec']))
    second = EvidenceGraph(tmp_path / 'agent_memory.db', clock=lambda: setup['clock'][0])
    try:
        assert second.replay(result['replay_evidence_hash'])['verdict'] == 'CONFIRMED'
    finally: second.close()


@pytest.mark.parametrize('end', [1000.0, float('inf'), float('nan'), 1000000.0])
def test_invalid_ttl_never_enters_evidence_store(setup, end):
    with pytest.raises(EvidenceError): setup['graph'].observe(setup['base']('permission', expires_at=end))


def test_all_relation_types_have_hash_context_and_ttl(setup):
    g = setup['graph']
    executor(setup).execute(g.build_plan(setup['spec']))
    before = g.evidence(setup['spec']['captures']['owner'])
    after = copy.deepcopy(before); after['response']['body']['uses'] = 1
    before['response']['body']['uses'] = 0
    g.changes_state(g.observe(before), g.observe(after), 'uses')
    relations = [json.loads(r[0]) for r in g.db.execute('SELECT payload FROM p8_relations')]
    assert {r['kind'] for r in relations} == RELATIONS
    for r in relations:
        assert r['evidence_hashes'] and r['context'] == CONTEXT and r['expires_at'] == 2000


@pytest.mark.parametrize('bad', ['resource', 'identity', 'no_change', 'type'])
def test_state_edges_require_same_observed_resource_and_typed_change(setup, bad):
    g = setup['graph']
    before = g.evidence(setup['spec']['captures']['owner']); before['response']['body']['uses'] = 0
    after = copy.deepcopy(before); after['response']['body']['uses'] = 1
    if bad == 'resource': after['request']['url'] = NEGATIVE
    elif bad == 'identity': after['identity_ref'] = 'bob'
    elif bad == 'no_change': after['response']['body']['uses'] = 0
    else: after['response']['body']['uses'] = '1'
    with pytest.raises(EvidenceError): g.changes_state(g.observe(before), g.observe(after), 'uses')


def test_shared_outbox_projects_validated_edges_and_refuses_forged_relationships(setup, monkeypatch):
    import evidence_chaining
    memory = load_server('memory-server')
    g = setup['graph']; g.build_plan(setup['spec'])
    monkeypatch.setattr(evidence_chaining, 'EvidenceGraph', lambda path: EvidenceGraph(path, clock=lambda: setup['clock'][0]))
    monkeypatch.setattr(memory, 'DB_PATH', str(Path(setup['graph'].db.execute('PRAGMA database_list').fetchone()[2])))
    row = g.db.execute('SELECT payload FROM graph_outbox LIMIT 1').fetchone()
    payload = json.loads(row[0])
    memory._apply_graph_projection('evidence_relation', payload)
    assert memory.kg.G.has_node('evidence-edge:' + payload['relation_id'])
    memory._apply_graph_projection('evidence_relation', payload)
    for name in RELATIONS:
        assert memory.add_relationship('a', 'b', name).startswith('HATA:')
    g.invalidate(payload['relation']['evidence_hashes'][0])
    with pytest.raises(EvidenceError): memory._apply_graph_projection('evidence_relation', payload)


def test_static_chain_rules_never_upgrade_severity_or_reportability():
    reasoning = load_server('reasoning')
    chain = reasoning._build_chain(['ssrf', 'cloud_metadata_access', 'iam_credentials', 'cloud_account_takeover'], [0.7, 0.8, 0.7], ['a', 'b', 'c'])
    assert chain['severity'] is None and not chain['runnable'] and not chain['reportable']
    assert chain['verdict'] == 'UNCONFIRMED' and chain['validated_terminal_impact'] is None
    assert all(s['validation_status'] == 'unvalidated_edge' for s in chain['steps'][1:])
    text = reasoning.kill_chain_report(json.dumps(chain))
    assert 'Static hypothesis' in text and 'unvalidated_edge' in text
    assert 'does not increase finding severity' in text


def test_missing_store_and_evidence_oracle_without_contract_fail_closed(setup):
    manifest = setup['graph'].build_plan(setup['spec'])
    assert ChainExecutor(identities=setup['identities']).execute(manifest)['requests_sent'] == 0
    manifest.pop('evidence_chain'); manifest.pop('kind')
    assert not validate_manifest(manifest)['valid']


@pytest.mark.parametrize('after', ['producer', 'owner', 'negative', 'peer'])
def test_ttl_is_rechecked_after_each_runtime_observation(setup, after):
    g, spec = setup['graph'], setup['spec']
    g.register_job('running', spec)
    lab, count = ReadLab(), [0]
    send = lab.sender
    def sender(*args):
        result = send(*args)
        count[0] += 1
        if count[0] == ['producer', 'owner', 'negative', 'peer'].index(after) + 1:
            setup['clock'][0] = 2001
        return result
    lab.sender = sender
    result = executor(setup, lab=lab).execute(g.build_plan(spec))
    assert result['verdict'] == 'INCONCLUSIVE' and not result['success']
    assert g.job('running')['status'] == 'invalidated'
    assert result['requests_sent'] == count[0]


@pytest.mark.parametrize('safe', [False, True])
def test_completed_chain_invalidated_if_runtime_proof_is_revoked(setup, safe):
    g, spec = setup['graph'], setup['spec']
    g.register_job('completed', spec)
    result = executor(setup, lab=ReadLab(safe=safe)).execute(g.build_plan(spec))
    assert g.job('completed')['status'] == 'completed'
    g.invalidate(result['replay_evidence_hash'])
    assert g.job('completed')['status'] == 'invalidated'
    with pytest.raises(EvidenceError): g.replay(result['replay_evidence_hash'])


@pytest.mark.parametrize('change', ['object_url', 'wrong_control_route', 'same_control', 'future', 'credential'])
def test_explicit_source_and_replay_boundaries(setup, change):
    g, spec = setup['graph'], copy.deepcopy(setup['spec'])
    if change == 'object_url':
        spec = change_evidence(setup, 'resource_hash', lambda d: d['resource'].update(url=PRODUCER))
    elif change == 'wrong_control_route':
        spec = change_evidence(setup, 'negative', lambda d: d['request'].update(url='https://p8.test/api/unrelated/missing'))
    elif change == 'same_control':
        spec['captures']['negative'] = spec['captures']['peer']
    elif change == 'future':
        d = g.evidence(spec['captures']['producer']); d['observed_at'] = 1001
        with pytest.raises(EvidenceError): g.observe(d)
        return
    else:
        manifest = g.build_plan(spec)
        result = executor(setup).execute(manifest)
        saved = g.evidence(result['replay_evidence_hash'])
        exchanges = {name: g.evidence(h) for name, h in saved['exchange_hashes'].items()}
        exchanges['peer']['credential_hash'] = digest({'Cookie': 'synthetic=alice'})
        outcome = g.seal_replay(manifest, exchanges)
        assert outcome['verdict'] == 'INCONCLUSIVE'
        return
    assert not compile_evidence_chain(g, spec)['runnable']


def test_expired_projection_is_retained_as_failed_outbox_job(setup, monkeypatch):
    import evidence_chaining
    memory = load_server('memory-server')
    g = setup['graph']; g.build_plan(setup['spec'])
    monkeypatch.setattr(evidence_chaining, 'EvidenceGraph', lambda path: EvidenceGraph(path, clock=lambda: setup['clock'][0]))
    monkeypatch.setattr(memory, 'DB_PATH', g.db.execute('PRAGMA database_list').fetchone()[2])
    # Lazy initialization replays pending projections before the explicit retry.
    assert memory.kg.G is not None
    rid = g.db.execute('SELECT id FROM graph_outbox LIMIT 1').fetchone()[0]
    attempts = g.db.execute('SELECT attempts FROM graph_outbox WHERE id=?', (rid,)).fetchone()[0]
    setup['clock'][0] = 2001
    assert memory._process_graph_job(rid) == 'expired_relation'
    row = g.db.execute('SELECT status,attempts FROM graph_outbox WHERE id=?', (rid,)).fetchone()
    assert tuple(row) == ('failed', attempts + 1)
