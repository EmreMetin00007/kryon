"""Offline P6 contracts. Transports, receipts and accounts are synthetic."""
import copy
import json
import sqlite3
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
for part in ('scripts', 'mcp-servers/mcp-hunter', 'mcp-servers/mcp-memory-server', 'mcp-servers/mcp-validator'):
    sys.path.insert(0, str(ROOT / part))

from cco_hunter_core.experiments import (  # noqa: E402
    ROUTES, PASSIVE_ADAPTERS, build_experiment, build_authz_experiment,
    execute_experiment, route_experiment, readonly_permission, protocol_access, tool_lifecycle,
)
from cco_hunter_core.testplan import plan_from_hypothesis, execute_test_plan  # noqa: E402
from cco_hunter_core.variants import build_executable_variants  # noqa: E402
from cco_hunter_core.loop import execute_web_loop  # noqa: E402
from cco_hunter_core.request_context import bind_policy_gate, store_context, policy_scoped, readonly_operation  # noqa: E402
from cco_surface_core.mutation import mutate_request, request_slot, replace_json_slot  # noqa: E402
from cco_surface_core.operation import graphql_operation  # noqa: E402
from cco_surface_core.store import ingest_records  # noqa: E402
from cco_validator_core.experiment_context import scoped_payloads, observed_baseline  # noqa: E402
from conftest import load_server  # noqa: E402

BASE = 'https://api.test/search?q=observed&tag=a&tag=b&blank='
CAPS = {r['tool']: True for r in ROUTES.values()}


def item(**changes):
    return {'url': BASE, 'method': 'GET', 'vuln_class': 'sql_injection', 'location': 'query', 'param': 'q',
            'operation_id': 'search-v1', 'observation_id': 5, 'identity': 'alice', 'resource_owner': 'bob',
            'resource_key': 'resource-1', 'state_key': 'screen-1', 'variant_key': 'boolean-v1', **changes}


def context(**changes):
    return {'url': BASE, 'method': 'GET', 'baseline_headers': {'X-Tenant': 'synthetic-tenant'}, **changes}


def plan(**changes):
    return build_experiment(item(), context(), "observed' AND 1=2", capabilities=CAPS, **changes)


def response(**changes):
    return {'ok': True, 'status': 200, 'text': '{"data":[{"id":"synthetic"}]}', **changes}


@pytest.mark.parametrize('kind', list(ROUTES))
def test_common_routes_declare_carriers_permissions_and_oracles(kind):
    row = ROUTES[kind]
    assert row['tool'] and row['carriers'] and row['oracle']
    assert {'scope', 'approval', 'wire_budget'} <= set(row['permissions'])


@pytest.mark.parametrize('kind,prerequisite', [('xss_reflected', 'browser_execution'), ('ssrf', 'oob_collector'),
                                              ('bola', 'access_context'), ('bfla', 'access_context')])
def test_missing_oracle_dependencies_are_explicit(kind, prerequisite):
    routed = route_experiment(item(vuln_class=kind), CAPS)
    assert routed['available'] and routed['applicable'] and not routed['runnable']
    assert routed['reason'] == 'missing_' + prerequisite
    assert not routed['executed'] and not routed['validated']


def test_unavailable_and_inapplicable_are_different():
    assert route_experiment(item(), {})['reason'] == 'validator_unavailable'
    assert route_experiment(item(vuln_class='ssrf', location='json'), CAPS,
                            {'oob_collector': True})['reason'] == 'unsupported_carrier'


@pytest.mark.parametrize('kind', ['jwt', 'oauth'])
def test_protocol_label_is_not_flow_evidence(kind):
    routed = route_experiment(item(vuln_class=kind, protocol=kind), CAPS)
    assert routed['reason'] == 'observed_flow_required' and not routed['applicable']
    prerequisites = {kind + '_flow': True, 'oauth_oracle': True}
    assert route_experiment(item(vuln_class=kind), CAPS, prerequisites)['runnable']


@pytest.mark.parametrize('adapter', PASSIVE_ADAPTERS)
def test_risky_adapters_are_passive_even_when_available(adapter):
    routed = route_experiment(item(vuln_class=adapter, protocol=adapter), {adapter: True})
    assert routed['mode'] == 'passive_inventory'
    assert routed['available'] and routed['applicable'] and not routed['runnable']


def test_disabled_hooks_never_execute_or_claim_validation():
    def forbidden(*_):
        pytest.fail('passive adapter executed')
    report = execute_web_loop(BASE, live=True, crawl=False,
        surface_hooks={k: forbidden for k in (*PASSIVE_ADAPTERS, 'jwt_kid_jku', 'graphql_suggestion')})
    assert report['surface_probes'] == []
    assert all(not s['executed'] and not s['validated'] for s in report['tool_states'])
    assert not any(k in report['steps'] for k in PASSIVE_ADAPTERS)


def test_lifecycle_flags_never_skip_a_stage():
    assert not tool_lifecycle(available=True, applicable=True, runnable=False,
                              executed=True, validated=True)['executed']
    assert not tool_lifecycle(available=False, applicable=True)['applicable']
    assert not tool_lifecycle(available=True, applicable=True, runnable=True,
                              executed=False, validated=True)['validated']


@pytest.mark.parametrize('carrier,name,path,packet', [
    ('query', 'q', None, {'method': 'GET', 'url': BASE, 'headers': {'X-Keep': 'yes'}}),
    ('json', 'needle', ['filter', 'rows', 1, 'needle'], {'method': 'POST', 'url': BASE, 'headers': {},
        'json_body': {'filter': {'rows': [{'needle': 'first'}, {'needle': 'observed', 'required': 8}]}, 'csrf': 'fixture'}}),
    ('form', 'q', None, {'method': 'POST', 'url': BASE, 'headers': {}, 'data': 'q=observed&tag=a&tag=b&csrf=fixture'}),
    ('header', 'x-search', None, {'method': 'GET', 'url': BASE, 'headers': {'X-Search': 'observed', 'X-Keep': 'yes'}}),
    ('cookie', 'search', None, {'method': 'GET', 'url': BASE, 'headers': {'Cookie': 'search=observed; csrf=fixture', 'X-Keep': 'yes'}}),
    ('path', 'id', [2], {'method': 'GET', 'url': 'https://api.test/items/observed/detail?keep=1', 'headers': {}}),
])
def test_single_slot_preserves_siblings_and_input(carrier, name, path, packet):
    original = copy.deepcopy(packet)
    assert request_slot(packet, carrier, name, path) == 'observed'
    changed = mutate_request(packet, carrier, name, 'new/value', path)
    assert packet == original and changed['method'] == original['method']
    restored = mutate_request(changed, carrier, name, 'observed', path)
    assert restored == original


@pytest.mark.parametrize('path', [['missing'], ['rows', 3], ['rows', -1], ['rows', True], ['rows', '0'], []])
def test_missing_and_invalid_array_slots_do_not_repair_baseline(path):
    body = {'rows': ['observed'], 'keep': 8}
    before = copy.deepcopy(body)
    with pytest.raises(ValueError):
        replace_json_slot(body, path, 'payload')
    assert body == before


@pytest.mark.parametrize('replacement', [None, 0, False, ['nested', {'value': 2}], {'array': [1, 2]}])
def test_type_and_nested_variants_derive_from_real_slots(replacement):
    assert replace_json_slot({'q': 'observed', 'csrf': 'fixture'}, ['q'], replacement) == {
        'q': replacement, 'csrf': 'fixture'}


def test_repeated_siblings_survive_and_target_occurrence_is_explicit():
    request = {'method': 'GET', 'url': BASE + '&q=second', 'headers': {}}
    with pytest.raises(ValueError, match='ambiguous'):
        mutate_request(request, 'query', 'q', 'probe')
    out = mutate_request(request, 'query', 'q', 'probe', occurrence=1)
    assert parse_qsl(urlsplit(out['url']).query, keep_blank_values=True) == [
        ('q', 'observed'), ('tag', 'a'), ('tag', 'b'), ('blank', ''), ('q', 'probe')]


@pytest.mark.parametrize('carrier', ['query', 'form'])
def test_sibling_encoding_and_empty_separators_are_preserved(carrier):
    encoded = 'q=observed&signed=a%20b&literal=%2f%2F&&blank=&bare'
    packet = {'url': 'https://api.test/?' + encoded, 'method': 'POST', 'headers': {}, 'data': encoded}
    out = mutate_request(packet, carrier, 'q', 'probe value')
    actual = urlsplit(out['url']).query if carrier == 'query' else out['data']
    assert actual == 'q=probe+value&signed=a%20b&literal=%2f%2F&&blank=&bare'


@pytest.mark.parametrize('carrier,packet,payload', [
    ('header', {'url': BASE, 'headers': {'q': 'observed'}}, 'x\r\nHost: evil'),
    ('cookie', {'url': BASE, 'headers': {'Cookie': 'q=observed; keep=yes'}}, 'x; keep=no'),
])
def test_one_slot_cannot_create_an_extra_header_or_cookie(carrier, packet, payload):
    with pytest.raises(ValueError):
        mutate_request(packet, carrier, 'q', payload)


def test_no_generic_body_or_race_is_generated_from_schema_names():
    p = plan_from_hypothesis({'path': '/checkout', 'body_fields': ['quantity']},
                              'sql_injection', capabilities=CAPS)
    assert p['experiment']['status'] == 'blocked'
    assert p['steps'] == [] and '"value"' not in json.dumps(p)


def test_testplan_executes_manifest_stages_with_oracle_evidence():
    p = plan_from_hypothesis({**item(), 'request_context': context(), 'mutation': 'probe'},
                              'sql_injection', target='https://api.test', capabilities=CAPS)
    calls = []
    receipt = {'validation_id': 'fixture-receipt', 'verdict': 'CONFIRMED'}
    out = execute_test_plan(p, lambda r: calls.append(r) or response(),
                            oracle=lambda *_: receipt, verify=lambda *_: True)
    assert out['status'] == 'confirmed' and out['requests_executed'] == 3
    assert [s['role'] for s in out['observations']] == ['baseline', 'mutation', 'negative_control']
    assert calls[0] == calls[2] and calls[1] != calls[0]


@pytest.mark.parametrize('bad', [response(status=s) for s in (400, 401, 403, 422, 429, 500)] + [
    response(ok=False), response(text='{"success":false}'), response(text='{"error":"bad"}')])
def test_invalid_baseline_stops_before_mutation(bad):
    calls = []
    out = execute_experiment(plan(), lambda r: calls.append(r) or bad,
                             lambda *_: pytest.fail('oracle called'), lambda *_: True)
    assert out['status'] == 'inconclusive' and len(calls) == 1
    assert not out['lifecycle']['validated']


@pytest.mark.parametrize('budget', [0, 1, 2, False, -1])
def test_insufficient_budget_does_not_send_or_close_hypothesis(budget):
    calls = []
    out = execute_experiment(plan(), lambda r: calls.append(r), lambda *_: {}, lambda *_: True,
                             max_requests=budget)
    assert out['reason'] == 'budget_exhausted' and out['status'] == 'blocked' and calls == []


def test_failed_negative_control_cannot_be_a_clean_result():
    responses = iter([response(), response(), response(status=429)])
    out = execute_experiment(plan(), lambda _: next(responses), lambda *_: pytest.fail('oracle called'), lambda *_: True)
    assert out['status'] == 'inconclusive' and 'negative_control' in out['reason']


@pytest.mark.parametrize('receipt', [{}, {'verdict': 'CONFIRMED'},
    {'validation_id': 'forged', 'verdict': 'CONFIRMED'}, {'validation_id': 'forged', 'verdict': 'UNCONFIRMED'}])
def test_untrusted_or_incomplete_receipts_do_not_validate(receipt):
    out = execute_experiment(plan(), lambda _: response(), lambda *_: receipt, lambda *_: False)
    assert out['status'] == 'inconclusive' and not out['lifecycle']['validated']
    assert 'synthetic-tenant' not in repr(out)


@pytest.mark.parametrize('key,value', [('identity', 'carol'), ('resource_key', 'r2'), ('state_key', 's2'),
                                     ('variant_key', 'v2'), ('operation_id', 'op2'), ('observation_id', 6)])
def test_experiment_identity_preserves_p5_isolation(key, value):
    first = plan()
    other = build_experiment(item(**{key: value}), context(), "observed' AND 1=2", capabilities=CAPS)
    assert first['experiment_id'] != other['experiment_id']
    assert first['binding'] != other['binding']


def test_post_requires_exact_policy_not_schema_or_llm_readonly_flags():
    request = {'method': 'POST', 'url': 'https://api.test/search'}
    rule = {**request, 'operation_id': 'op-query', 'read_only': True}
    assert readonly_permission(request, {'readonly_operations': [rule]}, 'op-query')
    for wrong in [{'read_only': True}, {'readonly_operations': [{**rule, 'url': BASE}]},
                  {'readonly_operations': [{**rule, 'operation_id': 'other'}]},
                  {'readonly_operations': [{**rule, 'method': 'GET'}]}]:
        assert not readonly_permission(request, wrong, 'op-query')
    assert not readonly_permission({**request, 'method': 'DELETE'}, {'readonly_operations': [rule]}, 'op-query')


def test_policy_scoped_post_uses_exact_operation_and_wire_gate(monkeypatch):
    import policy_engine
    from cco_hunter_core.request_context import current_policy_gate
    rule = {'method': 'POST', 'url': 'https://api.test/search', 'operation_id': 'op-query', 'read_only': True}
    class Engine:
        program_policy = {'readonly_operations': [rule]}
        def validate_wire_invocation(self, _tool, values):
            return {'allowed': values['url'] == rule['url']}
    monkeypatch.setattr(policy_engine, 'PolicyEngine', Engine)
    @policy_scoped('hunter_run_web_loop')
    def send(operation):
        with readonly_operation(operation):
            return current_policy_gate()('POST', rule['url'], {})
    assert send('op-query')[0] is True
    assert send('other')[0] is False


def graphql_context(kind='query'):
    document = f'{kind} Search($needle:String!) {{ search(q:$needle) {{ id }} }}'
    descriptor = graphql_operation(document, 'Search')
    return context(url='https://api.test/graphql', method='POST', operation=descriptor,
        parameter_path=['variables', 'needle'], baseline_json={
            'query': document, 'operationName': 'Search', 'variables': {'needle': 'observed', 'keep': 'fixture'}})


def test_graphql_variables_keep_document_operation_and_sibling_variables():
    ctx = graphql_context()
    it = item(url=ctx['url'], method='POST', location='json', param='needle')
    policy = {'readonly_operations': [{'method': 'POST', 'url': ctx['url'], 'operation_id': it['operation_id'], 'read_only': True}]}
    p = build_experiment(it, ctx, 'probe', capabilities=CAPS, policy=policy)
    assert p['status'] == 'ready'
    body = p['stages'][1]['request']['json_body']
    assert body == {**ctx['baseline_json'], 'variables': {'needle': 'probe', 'keep': 'fixture'}}
    assert protocol_access({'operation': ctx['operation']})['dimensions'] == ['operation', 'field', 'variable']
    assert protocol_access(item())['dimensions'] == ['object', 'function', 'field']


@pytest.mark.parametrize('kind', ['mutation', 'subscription'])
def test_graphql_nonqueries_do_not_gain_readonly_from_post_policy(kind):
    ctx = graphql_context(kind)
    p = build_experiment(item(url=ctx['url'], method='POST', location='json', param='needle'), ctx,
                          'probe', capabilities=CAPS)
    assert p['reason'] == 'graphql_readonly_operation_required'


def test_fanout_has_only_observed_carrier_and_keeps_required_siblings():
    variants = build_executable_variants('sql_injection', BASE, 'q', BASE)
    assert len(variants) == 1 and variants[0]['method'] == 'GET'
    assert [pair for pair in parse_qsl(urlsplit(variants[0]['url']).query) if pair[0] == 'tag'] == [('tag', 'a'), ('tag', 'b')]
    assert build_executable_variants('sql_injection', BASE, 'invented', BASE) == []
    assert build_executable_variants('command_injection', BASE, 'q', BASE) == []


def test_validator_adapter_preserves_nested_array_and_literal_marker_sibling(tmp_path, monkeypatch):
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    hunter = load_server('hunter')
    validator = load_server('validator')
    seen = []
    monkeypatch.setattr(validator, '_request', lambda method, url, **kw: seen.append((method, url, kw)) or response())
    def check(url, param='', method='GET', body_template='', headers_json='{}', carrier='query'):
        validator._send_payload(url, observed_baseline('wrong-default'), param=param, method=method)
        validator._send_payload(url, 'a"b', param=param, method=method)
        validator._send_payload(url, observed_baseline('wrong-default'), param=param, method=method)
        return json.dumps({'verdict': 'INCONCLUSIVE'})
    monkeypatch.setattr(validator, 'validate_sqli', check)
    monkeypatch.setattr(hunter, '_load_peer', lambda *_: validator)
    monkeypatch.setattr(hunter, '_record_hypothesis_state', lambda *_: None)
    it = item(url='https://api.test/search', method='POST', location='json', param='needle',
              resource_key='a' * 64, state_key='b' * 64, variant_key='c' * 64)
    body = {'rows': [{'needle': 'observed', 'keep': '{{PAYLOAD}}'}], 'csrf': 'fixture'}
    db = tmp_path / 'agent_memory.db'
    ingest_records([{'url': it['url'], 'method': 'POST', 'params': [
        {'name': 'needle', 'in': 'json', 'path': ['rows', 0, 'needle'], 'sample': 'observed'}]}],
        target='https://api.test', db_path=str(db))
    with sqlite3.connect(db) as conn:
        operation, observation = conn.execute('SELECT operation_id,observation_id FROM surface_operation_heads').fetchone()
    it.update(operation_id=operation, observation_id=observation)
    ctx = {**context(url=it['url'], method='POST', baseline_json=body,
                      parameter_path=['rows', 0, 'needle']),
           **{k: it[k] for k in ('vuln_class', 'param', 'location', 'method', 'operation_id', 'observation_id')}}
    it['request_ref'] = store_context(ctx)
    with bind_policy_gate(lambda *_: (True, 'fixture')):
        result = hunter._loop_validate(it)
    assert len(seen) == 3, result
    assert len(seen) == 3 and all(r[0] == 'POST' for r in seen)
    assert json.loads(seen[0][2]['data']) == body == json.loads(seen[2][2]['data'])
    assert json.loads(seen[1][2]['data']) == {'rows': [{'needle': 'a"b', 'keep': '{{PAYLOAD}}'}], 'csrf': 'fixture'}


def test_scoped_payload_context_is_restored_after_exception():
    assert observed_baseline('default') == 'default'
    with pytest.raises(RuntimeError), scoped_payloads(lambda _: {}, 'observed'):
        assert observed_baseline('default') == 'observed'
        raise RuntimeError('fixture')
    assert observed_baseline('default') == 'default'


def test_authz_plan_uses_p4_denied_cell_and_one_identity_swap():
    from test_p4_authz_matrix import actor, resource
    from authz_matrix import resource_key
    identities = {'alice': actor('a'), 'bob': actor('b')}
    for name, actor in identities.items():
        actor['headers'] = {'Authorization': 'synthetic-' + name}
    obj = resource(url=BASE)
    it = item(vuln_class='bola', identity='bob', attacker_identity='bob', resource_owner='alice', resource_key=resource_key(obj),
              category='same_tenant_other_user')
    p = build_authz_experiment(it, context(), identities, [obj], capabilities=CAPS)
    assert p['status'] == 'ready'
    baseline, mutation, control = [s['request'] for s in p['stages'][:3]]
    assert baseline == control and baseline['url'] == mutation['url']
    assert baseline['headers']['Authorization'] != mutation['headers']['Authorization']
    obj['access_rule']['visibility'] = 'public'
    assert build_authz_experiment(it, context(), identities, [obj], capabilities=CAPS)['status'] == 'blocked'


@pytest.mark.parametrize('slot', ['baseline', 'mutation', 'negative_control'])
def test_tampered_siblings_stop_before_transport(slot):
    p = plan()
    stage = next(s for s in p['stages'] if s['role'] == slot)
    stage['request']['headers']['X-Tenant'] = 'different'
    calls = []
    out = execute_experiment(p, lambda r: calls.append(r) or response(), lambda *_: {}, lambda *_: True)
    assert out['status'] == 'blocked' and calls == []


@pytest.mark.parametrize('document,expected', [
    ('query Q($id:ID!){ renamed:user(id:$id){ id profile{ name } } }', ['user', 'user.id', 'user.profile', 'user.profile.name']),
    ('query Q{ user { ...F } } fragment F on User { id email }', ['user', 'user.id', 'user.email']),
    ('query Q{ user @include(if:true) { ... on User { id } } }', ['user', 'user.id']),
])
def test_graphql_inventory_records_schema_fields_not_aliases_or_argument_values(document, expected):
    assert graphql_operation(document, 'Q')['fields'] == expected


def test_missing_mutation_and_changed_graphql_document_are_blocked():
    p = plan_from_hypothesis({**item(), 'request_context': context()}, 'sql_injection',
                              target='https://api.test', capabilities=CAPS)
    assert p['experiment']['reason'] == 'observed_mutation_required'
    ctx = graphql_context()
    ctx['baseline_json']['query'] = 'query Search { privateData }'
    p = build_experiment(item(url=ctx['url'], method='POST', location='json', param='needle'), ctx,
                          'probe', capabilities=CAPS)
    assert p['reason'] == 'graphql_operation_context_mismatch'


def test_manifest_target_origin_must_match_all_requests():
    p = plan_from_hypothesis({**item(), 'request_context': context(), 'mutation': 'probe'},
                              'sql_injection', target='https://other.test', capabilities=CAPS)
    calls = []
    out = execute_test_plan(p, lambda r: calls.append(r))
    assert not out['valid'] and calls == []


@pytest.mark.parametrize('failed_role', ['baseline', 'negative_control'])
def test_scoped_xss_failing_control_never_becomes_clean_or_confirmed(tmp_path, monkeypatch, failed_role):
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    validator = load_server('validator')
    calls = []
    def send(_url, payload, **_kwargs):
        calls.append(payload)
        position = 1 if failed_role == 'baseline' else 3
        return response(status=500 if len(calls) == position else 200, text=str(payload))
    monkeypatch.setattr(validator, '_send_payload', send)
    with scoped_payloads(lambda _: {}, 'observed'):
        out = json.loads(validator.validate_xss_reflection(BASE, param='q'))
    assert out['verdict'] == 'INCONCLUSIVE'
    assert len(calls) == (1 if failed_role == 'baseline' else 3)


def test_scoped_reflection_is_not_xss_execution(tmp_path, monkeypatch):
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    validator = load_server('validator')
    monkeypatch.setattr(validator, '_send_payload', lambda _url, payload, **kw: response(text=str(payload)))
    with scoped_payloads(lambda payload: mutate_request({'url': BASE, 'method': 'GET', 'headers': {}},
                                                        'query', 'q', payload), 'observed'):
        out = json.loads(validator.validate_xss_reflection(BASE, param='q'))
    assert out['verdict'] == 'INCONCLUSIVE' and not out['evidence']['execution']['observed']
    assert len(out['request_evidence']) == 3


def test_scoped_control_detects_graphql_application_errors():
    from cco_validator_core.controls import usable_control
    from cco_hunter_core.request_context import baseline_decision
    operation = {'protocol': 'graphql'}
    with scoped_payloads(lambda _: {}, 'observed', baseline_check=lambda r: baseline_decision(r, operation)['eligible']):
        assert not usable_control(response(text='{"errors":[{"message":"denied"}]}'), baseline=True)
        assert usable_control(response(text='{"data":{"search":[]}}'), baseline=True)


def test_surface_captured_array_mutates_one_leaf():
    from cco_surface_core.fuzz import apply_canary
    body = {'rows': [{'needle': 'observed', 'required': 'keep'}], 'csrf': 'fixture'}
    record = {'url': BASE, 'method': 'POST', 'content_type': 'application/json',
        '_captured_wire': {'method': 'POST', 'url': BASE, 'headers': {}, 'body': body},
        'params': [{'name': 'needle', 'in': 'json', 'path': ['rows', 0, 'needle'], 'sample': 'observed'}]}
    result = apply_canary(record, 'needle', 'json', 'probe')
    assert result['baseline_json'] == body
    assert result['json_body'] == {'rows': [{'needle': 'probe', 'required': 'keep'}], 'csrf': 'fixture'}


@pytest.mark.parametrize('allowed,verdict', [(False, 'CONFIRMED'), (True, 'UNCONFIRMED')])
def test_redirect_uses_negative_control_and_explicit_destination_allowlist(tmp_path, monkeypatch, allowed, verdict):
    from cco_validator_core.egress import scoped_wire_gate
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    validator = load_server('validator')
    monkeypatch.setattr(validator.secrets, 'token_hex', lambda *_: 'fixed')
    calls = []
    def send(_url, payload, **_kwargs):
        calls.append(payload)
        return response(status=302, location='/home' if payload == 'observed' else 'https://fixed.cco-validate.test/')
    monkeypatch.setattr(validator, '_send_payload', send)
    def gate(*_):
        return True, 'synthetic-fixture'
    gate.program_policy = lambda: {'open_redirect': {'allowed_hosts': ['fixed.cco-validate.test'] if allowed else []}}
    with scoped_wire_gate(gate), scoped_payloads(lambda payload: mutate_request(
            {'url': BASE, 'method': 'GET', 'headers': {}}, 'query', 'q', payload), 'observed'):
        out = json.loads(validator.validate_open_redirect(BASE, param='q'))
    assert out['verdict'] == verdict
    assert calls[0] == calls[2] == 'observed'


def test_scoped_ssrf_invalid_baseline_never_sends_callback_probe(tmp_path, monkeypatch):
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    validator = load_server('validator')
    monkeypatch.setattr(validator, '_oob_host_in_scope', lambda *_: True)
    calls = []
    monkeypatch.setattr(validator, '_send_payload', lambda _url, payload, **kw:
                        calls.append(payload) or response(status=500))
    monkeypatch.setattr(validator, '_store_oob_challenge', lambda *_: pytest.fail('pending challenge created'))
    with scoped_payloads(lambda _: {}, 'observed'):
        out = json.loads(validator.validate_ssrf_oob('https://api.test/?q=observed&keep=1', 'callback.test', param='q'))
    assert out['verdict'] == 'INCONCLUSIVE' and calls == ['observed']
