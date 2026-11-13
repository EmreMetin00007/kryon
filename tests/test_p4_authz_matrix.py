"""P4 regression fixtures; no transport or provider is involved."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from authz_matrix import (  # noqa: E402
    access_expectation, block_identity_work, build_identity_matrix, identity_fact,
    object_access_blocked, resume_identity_work, same_principal,
)
from object_identity import ResourceReferences, bind_resource_route, normalize_object_id, object_id_key  # noqa: E402
from conftest import load_server  # noqa: E402

UUID = '5080c899-12bf-4523-89ce-d91a5ce3d1f4'
URL = 'https://own.test/api/orders/' + UUID


def actor(principal, tenant='t1', role='member'):
    return {'test_data_only': True, 'headers': {'Cookie': 'synthetic=' + principal},
            'identity_facts': [{'field': f, 'value': v, 'source': 'operator',
                                'evidence': 'fixture:accounts', 'confidence': 'declared'}
                               for f, v in {'principal': principal, 'tenant': tenant,
                                            'role': role, 'authority': 'own.test'}.items()]}


def resource(**kwargs):
    return {'resource_id': UUID, 'family': 'orders', 'tenant': 't1',
            'owner_identity': 'alice', 'test_data_only': True,
            'access_rule': {'visibility': 'private', 'owner_only': True,
                            'authentication_required': True, 'source': 'operator',
                            'evidence': 'fixture:policy'}, **kwargs}


@pytest.fixture
def actors():
    return {'alice': actor('a'), 'bob': actor('b'),
            'carol': actor('c', 't2'), 'dana': actor('d', role='admin')}


def test_all_five_categories_have_concrete_actors(actors):
    matrix = build_identity_matrix(actors, [resource()])
    assert {r['category'] for r in matrix['matrix']} == {
        'owner', 'same_tenant_other_user', 'cross_tenant_user', 'different_role', 'anonymous'}
    assert not matrix['missing_coverage']
    assert all(r['verdict'] == 'NOT_TESTED' for r in matrix['matrix'])


@pytest.mark.parametrize('principal,expected', [('a', True), ('b', False)])
def test_tokens_never_establish_user_identity(principal, expected):
    a, b = actor('a'), actor(principal)
    b['headers'] = {'Authorization': 'Bearer rotated-token'}
    assert same_principal(a, b) is expected
    assert same_principal({'headers': a['headers']}, {'headers': b['headers']}) is None


@pytest.mark.parametrize('change', ['missing', 'conflict', 'unsourced', 'authority'])
def test_uncertain_principal_cannot_fill_another_user_group(change):
    a, b = actor('a'), actor('b')
    if change == 'missing':
        b['identity_facts'] = []
    elif change == 'conflict':
        b['identity_facts'].append({**b['identity_facts'][0], 'value': 'c'})
    elif change == 'unsourced':
        b['identity_facts'][0]['evidence'] = ''
    else:
        b['identity_facts'][-1]['value'] = 'another-issuer'
    matrix = build_identity_matrix({'alice': a, 'bob': b}, [resource()])
    assert not any(r['identity'] == 'bob' for r in matrix['matrix'])


def test_missing_cross_tenant_does_not_block_owner_or_anonymous():
    m = build_identity_matrix({'alice': actor('a')}, [resource()])
    assert {r['category'] for r in m['missing_coverage']} == {
        'cross_tenant_user', 'same_tenant_other_user', 'different_role'}
    assert {r['category'] for r in m['matrix'] if r['status'] == 'ready'} == {'owner', 'anonymous'}


@pytest.mark.parametrize('visibility,expected', [('public', 'allow'), ('shared', 'allow'), ('private', 'deny')])
def test_public_shared_are_not_denials(visibility, expected):
    r = resource()
    r['access_rule'].update(visibility=visibility, shared_principals=['b'])
    assert access_expectation(r, actor('b'), 'same_tenant_other_user') == expected


def test_ownership_is_not_a_privacy_rule():
    assert access_expectation(resource(access_rule={}), actor('b'), 'cross_tenant_user') == 'unknown'


def test_field_rules_are_separate_from_object_rules():
    r = resource()
    r['access_rule']['denied_field_roles'] = {'salary': ['member']}
    assert access_expectation(r, actor('b'), 'different_role', 'salary') == 'deny'
    assert access_expectation(r, actor('b'), 'different_role', 'name') == 'unknown'


@pytest.mark.parametrize('value', [UUID, 'tenant:order/opaque=00', '0001',
    {'format': 'composite', 'value': {'tenant': 't1', 'order': UUID}}])
def test_identifier_roundtrip_and_resource_flow(value):
    assert normalize_object_id(normalize_object_id(value)) == normalize_object_id(value)
    refs = ResourceReferences()
    keys = [refs.observe(tenant='t1', family='orders', resource_id=value,
                         stage=s, evidence='fixture:' + s) for s in ('list', 'detail', 'download', 'export')]
    assert len(set(keys)) == 1
    assert len(refs.resources[keys[0]]['observations']) == 4
    assert keys[0] != refs.observe(tenant='t2', family='orders', resource_id=value,
                                  stage='detail', evidence='fixture:detail')


def test_composite_key_is_order_independent():
    assert object_id_key({'format': 'composite', 'value': {'x': UUID, 'y': 1}}) == object_id_key(
        {'format': 'composite', 'value': {'y': 1, 'x': UUID}})


def test_uuid_binds_only_to_evidenced_slot():
    route = bind_resource_route('https://own.test/api/tenants/{tenant_id}/orders/{order_id}',
        'https://own.test/api/tenants/t1/orders/' + UUID, {'tenant_id': 't1', 'order_id': UUID})
    assert route['bindings']['order_id']['value'] == UUID


@pytest.mark.parametrize('bindings,url', [({'order_id': UUID}, URL),
    ({'tenant_id': UUID, 'order_id': 't1'}, 'https://own.test/api/tenants/t1/orders/' + UUID)])
def test_uuid_does_not_guess_or_swap_slots(bindings, url):
    with pytest.raises(ValueError):
        bind_resource_route('https://own.test/api/tenants/{tenant_id}/orders/{order_id}', url, bindings)


def test_encoded_slash_cannot_span_route_segments():
    with pytest.raises(ValueError):
        bind_resource_route('https://own.test/{id}', 'https://own.test/a/b', {'id': 'a/b'})


def test_refresh_only_releases_matching_session_jobs(actors):
    rows = build_identity_matrix(actors, [resource()])['matrix']
    block_identity_work(rows, 'bob')
    rows += [{'identity': 'carol', 'status': 'blocked', 'reason': 'session_unavailable'},
             {'identity': 'bob', 'status': 'blocked', 'reason': 'scope_denied'},
             {'identity': 'bob', 'status': 'done', 'reason': ''}]
    before = copy.deepcopy(rows)
    resume_identity_work(rows, 'bob')
    for old, new in zip(before, rows):
        if old.get('blocked_identities') == ['bob']:
            assert new['status'] == 'ready'
        else:
            assert old == new


@pytest.mark.parametrize('visibility', ['public', 'shared'])
def test_public_shared_blocked_before_existing_oracle(visibility, monkeypatch):
    hunter = load_server('hunter')
    identities = {'alice': actor('a'), 'bob': actor('b')}
    identities['alice']['objects'] = [{'url': URL, 'marker': UUID, 'visibility': visibility}]
    monkeypatch.setattr(hunter, '_load_peer', lambda *a: pytest.fail('public resource reached oracle'))
    result = hunter._loop_authz_validate({'url': URL, 'vuln_class': 'bola', 'owned_object': True,
        'owner_identity': 'alice', 'attacker_identity': 'bob', 'owner_marker': UUID}, identities)
    assert result['verdict'] == 'INCONCLUSIVE'
    from cco_hunter_core.loop import _owned_authz_items
    assert _owned_authz_items({'url': URL, 'vuln_class': 'bola'}, identities) == []


def test_same_principal_rotation_is_blocked():
    assert object_access_blocked({}, actor('a'), actor('a'))
    assert not object_access_blocked({}, actor('a'), actor('b'))


def test_mcp_matrix_uses_evidenced_objects(actors):
    hunter = load_server('hunter')
    result = json.loads(hunter.build_authz_matrix(identities=json.dumps(actors), resources=json.dumps([resource()])))
    assert not result['missing_coverage']
    assert 'synthetic=' not in json.dumps(result)


def test_unattributed_account_does_not_gain_principal_from_role():
    assert identity_fact({'role': 'admin', 'headers': {'Authorization': 'token'}}, 'principal') is None


@pytest.mark.parametrize('visibility', ['public', 'shared'])
def test_discovery_metadata_overrides_blanket_private_declaration(visibility):
    from test_blind_identity_discovery import BASE, _identities, _fixture_transport, _permit
    from cco_hunter_core.blind_discovery import discover_owned_resources
    calls = []
    transport = _fixture_transport(calls)
    def fetch(url, headers):
        response = transport(url, headers)
        data = json.loads(response['text'])
        if 'owner_id' in data:
            data['visibility'] = visibility
        response['text'] = json.dumps(data)
        return response
    summary, enriched, candidates = discover_owned_resources(
        BASE, _identities(), fetch, _permit, allow_private_owned=True)
    assert not candidates
    assert all(not a.get('objects') for a in enriched.values())
    assert 'public/shared' in ' '.join(summary['reasons'])


def test_identity_facts_survive_encrypted_session_declaration(tmp_path, monkeypatch):
    load_server('hunter')
    from cco_surface_core import session_store
    from cco_hunter_core.access_context import session_identity
    monkeypatch.setenv('CCO_HOME', str(tmp_path))
    target = 'https://api.test/'
    session_store.put_session(target, 'alice', headers={'Cookie': 'session=synthetic'},
                              check_url=target + 'me', marker='alice')
    facts = actor('a')['identity_facts']
    session_store.bind_resources(target, 'alice', {'role': 'member', 'identity_facts': facts}, permits=lambda _: True)
    session_store.refresh_status(target, 'alice', lambda *_: (200, 'alice'))
    entry = session_store.verified_session(target, 'alice')
    restored = session_identity(entry, {'role': 'member'}, type('Scope', (), {'permits_url': lambda *a: True})())
    assert restored['identity_facts'] == facts
    index = session_store.vault_path().read_text()
    assert 'fixture:accounts' not in index and 'session=synthetic' not in index


def test_missing_identity_discovery_does_not_stop_independent_fuzz():
    load_server('hunter')
    from cco_hunter_core.loop import execute_web_loop
    called = []
    result = execute_web_loop('https://api.test/', live=True, crawl=False,
        identity_discover=lambda *a: ({'status': 'incomplete', 'requests': 0,
                                       'reasons': ['second identity unavailable']}, {}, []),
        fuzz=lambda *a, **kw: called.append('fuzz') or {'probes': 1, 'validator_queue': []})
    assert called == ['fuzz']
    assert any('second identity' in row['reason'] for row in result['skipped'])


def test_function_matrix_requires_denied_role_rule(actors):
    r = resource(kind='function')
    assert access_expectation(r, actors['dana'], 'different_role') == 'unknown'
    r['access_rule']['denied_roles'] = ['admin']
    assert access_expectation(r, actors['dana'], 'different_role') == 'deny'
    assert any(row['test_type'] == 'bfla' for row in build_identity_matrix(actors, [r])['matrix'])


def test_refresh_cannot_clear_another_identity_dependency():
    rows = [{'identity': 'bob', 'owner_identity': 'alice', 'status': 'ready', 'reason': ''}]
    block_identity_work(rows, 'alice')
    block_identity_work(rows, 'bob')
    resume_identity_work(rows, 'bob')
    assert rows[0]['status'] == 'blocked' and rows[0]['blocked_identities'] == ['alice']
    resume_identity_work(rows, 'alice')
    assert rows[0]['status'] == 'ready'


def test_missing_second_vault_account_is_not_a_fatal_binding_count(monkeypatch):
    hunter = load_server('hunter')
    seen = []
    def vault(*args, **kwargs):
        seen.append(kwargs['min_accounts'])
        return {'alice': actor('a')}
    monkeypatch.setattr(hunter, '_vault_test_identities', vault)
    monkeypatch.setattr(hunter, 'execute_web_loop', lambda *a, **kw: {'ok': True, 'skipped': [], 'errors': [], 'identities_count': len(kw['identities'])})
    result = json.loads(hunter.run_web_loop('https://api.test/', live=True, blind_discovery=True,
                                          session_bindings='{"alice":{}}'))
    assert seen == [1] and result['ok']


@pytest.mark.parametrize('mode', ['same_principal', 'public', 'unknown'])
def test_response_equality_does_not_establish_bola(mode):
    load_server('hunter')
    from cco_hunter_core.identity_pool import diff_verdict
    identities = {'alice': actor('a'), 'bob': actor('a' if mode == 'same_principal' else 'b')}
    if mode == 'unknown':
        identities['bob'].pop('identity_facts')
    result = diff_verdict({'alice': {'status': 200, 'body': 'shared-content'},
                           'bob': {'status': 200, 'body': 'shared-content'}},
                          identities=identities, resource={'visibility': 'public'} if mode == 'public' else {})
    assert not result['violations']


def test_mismatched_resource_slot_cannot_reach_candidate_binder():
    load_server('hunter')
    from cco_hunter_core.loop import _owned_authz_items
    identities = {'alice': actor('a'), 'bob': actor('b')}
    obj = {'url': URL, 'marker': UUID, 'resource_id': UUID, 'resource_param': 'order_id',
           'route_template': 'https://own.test/api/orders/{order_id}',
           'route_bindings': {'order_id': 'other-opaque'}}
    identities['alice']['objects'] = [obj]
    assert not _owned_authz_items({'url': obj['route_template'], 'vuln_class': 'bola'}, identities)
    obj['route_bindings']['order_id'] = UUID
    assert _owned_authz_items({'url': obj['route_template'], 'vuln_class': 'bola'}, identities)
