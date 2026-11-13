"""P5 observation feedback contracts. All requests and receipts are synthetic."""
import copy
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for part in ('scripts', 'mcp-servers/mcp-hunter', 'mcp-servers/mcp-memory-server'):
    sys.path.insert(0, str(ROOT / part))
from cco_surface_core import hypotheses as h  # noqa: E402
from cco_surface_core.store import ingest_records  # noqa: E402
from cco_hunter_core.feedback import build_feedback, persist_feedback  # noqa: E402
from cco_hunter_core.gap_queue import gap_plan  # noqa: E402
from cco_hunter_core.candidates import candidate_listener, publish_candidate, fair_queue  # noqa: E402
from conftest import load_server  # noqa: E402
from test_campaign_gap_bridge import setup, plan, sessions, schedule, evidence, BASE  # noqa: E402,F401
from test_campaign_session_resume import block, refresh  # noqa: E402

TARGET = 'https://api.test/'
CONTEXT = 'scope-policy-v1'


def row(**changes):
    return {'url': TARGET + 'orders/opaque-uuid?field=baseline', 'method': 'GET', 'operation_id': 'orders-detail',
            'carrier': 'query', 'param': 'field', 'identity': 'alice', 'resource_owner': 'bob',
            'resource_id': 'opaque-uuid', 'resource_family': 'orders', 'request_state': {'tab': 'details'},
            'variant_id': 'owner-control-v1', 'vuln_class': 'bola', 'observation_id': 7, 'run_id': 'run-1', **changes}


@pytest.fixture
def conn():
    with sqlite3.connect(':memory:') as db:
        yield db


@pytest.mark.parametrize('field,value', [('operation_id', 'orders-export'), ('carrier', 'body'),
    ('param', 'other'), ('identity', 'carol'), ('resource_owner', 'dana'), ('resource_id', 'other-uuid'),
    ('resource_family', 'invoices'), ('request_state', {'tab': 'export'}), ('variant_id', 'owner-control-v2'),
    ('vuln_class', 'bfla'), ('observation_id', 8), ('run_id', 'run-2'), ('method', 'HEAD'),
    ('url', TARGET + 'orders/opaque-uuid?field=other')])
def test_every_dimension_is_independent(field, value):
    assert h.dimension(TARGET, row(), CONTEXT)[0] != h.dimension(TARGET, row(**{field: value}), CONTEXT)[0]


def test_duplicate_observation_is_idempotent_and_never_unconfirms(conn):
    key = h.observe(conn, TARGET, row(), CONTEXT)
    for _ in range(3):
        assert h.observe(conn, TARGET, row(), CONTEXT) == key
    assert len(h.list_hypotheses(conn, TARGET)) == 1
    receipt = {'status': 'confirmed', 'validation_id': 'signed-receipt'}
    assert h.complete(conn, key, receipt, lambda *a: True)
    h.observe(conn, TARGET, row(), CONTEXT)
    assert not h.transition(conn, key, 'ready')
    assert h.list_hypotheses(conn, TARGET)[0]['status'] == 'confirmed'


@pytest.mark.parametrize('state', h.STATES[:5])
def test_nonterminal_lifecycle_is_distinct_from_task_completion(conn, state):
    key = h.observe(conn, TARGET, row(), CONTEXT)
    h.transition(conn, key, state, reason='budget_exhausted' if state == 'blocked' else '')
    assert h.list_hypotheses(conn, TARGET)[0]['status'] == state
    assert not h.complete(conn, key, {'status': 'done', 'validation_id': 'task-done'}, lambda *a: True)


@pytest.mark.parametrize('terminal', sorted(h.TERMINAL))
def test_terminal_status_requires_evidence_verifier(conn, terminal):
    key = h.observe(conn, TARGET, row(), CONTEXT)
    with pytest.raises(ValueError):
        h.transition(conn, key, terminal)
    assert not h.complete(conn, key, {'status': 'confirmed', 'validation_id': 'forged'}, lambda *a: False)
    assert h.list_hypotheses(conn, TARGET)[0]['status'] == 'proposed'


def test_negative_result_cannot_close_other_objects_or_variants(conn):
    first = h.observe(conn, TARGET, row(), CONTEXT)
    other = h.observe(conn, TARGET, row(variant_id='other-variant'), CONTEXT)
    assert h.complete(conn, first, {'status': 'tested_clean', 'validation_id': 'v1'}, lambda *a: True)
    states = {r['fingerprint']: r['status'] for r in h.list_hypotheses(conn, TARGET)}
    assert states == {first: 'tested_no_violation', other: 'proposed'}


def test_blocker_resolution_is_versioned_and_specific(conn):
    keys = [h.observe(conn, TARGET, row(identity=actor), CONTEXT) for actor in ('alice', 'carol')]
    for key, actor in zip(keys, ('alice', 'carol')):
        h.transition(conn, key, 'blocked', reason='session_unavailable',
                     blockers=[{'kind': 'session', 'subject': actor, 'version': 'old'}])
    assert h.resolve(conn, TARGET, CONTEXT, kind='session', subject='alice', previous_version='old', new_version='old') == []
    assert h.resolve(conn, TARGET, 'other-context', kind='session', subject='alice', previous_version='old', new_version='new') == []
    assert h.resolve(conn, TARGET, CONTEXT, kind='session', subject='alice', previous_version='old', new_version='new') == [keys[0]]
    states = {r['identity']: r['status'] for r in h.list_hypotheses(conn, TARGET)}
    assert states == {'alice': 'proposed', 'carol': 'blocked'}


def test_all_dependencies_must_change_and_budget_is_not_session(conn):
    key = h.observe(conn, TARGET, row(), CONTEXT)
    h.transition(conn, key, 'blocked', reason='session_unavailable', blockers=[
        {'kind': 'session', 'subject': 'alice', 'version': 'a1'},
        {'kind': 'budget', 'subject': 'campaign', 'version': 'b1'}])
    h.resolve(conn, TARGET, CONTEXT, kind='session', subject='alice', previous_version='a1', new_version='a2')
    state = h.list_hypotheses(conn, TARGET)[0]
    assert state['status'] == 'blocked' and state['blockers'][0]['kind'] == 'budget'


def test_readiness_quality_contribution_and_cost_priority():
    rows = [{'status': 'blocked', 'observation_quality': 999},
            {'status': 'ready', 'observation_quality': 1, 'estimated_requests': 1},
            {'status': 'ready', 'observation_quality': 3, 'estimated_requests': 5},
            {'status': 'ready', 'observation_quality': 3, 'estimated_requests': 2}]
    assert sorted(rows, key=h.priority) == [rows[3], rows[2], rows[1], rows[0]]
    assert h.priority({'estimated_seconds': float('nan')})


def test_new_surface_uuid_or_parameter_automatically_creates_hypotheses(tmp_path):
    db = tmp_path / 'memory.db'
    base = {'url': TARGET + 'orders/5080c899-12bf-4523-89ce-d91a5ce3d1f4?q=apple',
            'method': 'GET', 'sources': ['xhr'], 'params': [{'name': 'q', 'in': 'query', 'sample': 'apple'}]}
    ingest_records([base], db_path=str(db))
    with sqlite3.connect(db) as conn:
        before = h.list_hypotheses(conn, 'api.test')
    assert before
    ingest_records([base], db_path=str(db))
    with sqlite3.connect(db) as conn:
        assert len(h.list_hypotheses(conn, 'api.test')) == len(before)
    ingest_records([{**base, 'params': [*base['params'], {'name': 'sort', 'in': 'query', 'sample': 'date'}]}], db_path=str(db))
    ingest_records([{**base, 'url': TARGET + 'orders/another-opaque?q=apple'}], db_path=str(db))
    with sqlite3.connect(db) as conn:
        after = h.list_hypotheses(conn, 'api.test')
    assert len(after) > len(before)
    assert any(r['param'] == 'sort' for r in after)
    assert len({r['operation_id'] for r in after}) >= 2


def test_metadata_stores_hashes_and_not_credentials(conn):
    secret = 'synthetic-private-value'
    h.observe(conn, TARGET, row(url=TARGET + '?token=' + secret, resource_id=secret,
                               request_state={'cookie': secret}, variant_id=secret, headers={'Cookie': secret}), CONTEXT)
    assert secret not in json.dumps(h.list_hypotheses(conn, TARGET))
    assert secret not in ''.join(conn.iterdump())


def test_budget_exhaustion_stays_blocked(tmp_path):
    report = {'run_id': 'run-1', 'validation_queue': [row()],
              'validations': [{**row(), 'feedback_reason': 'budget_exhausted', 'verdict': 'UNCONFIRMED'}]}
    feedback = build_feedback(report)
    assert feedback[0]['status'] == 'blocked' and feedback[0]['reason_code'] == 'budget_exhausted'
    path = str(tmp_path / 'feedback.db')
    persist_feedback(path, TARGET, CONTEXT, report, type('Scope', (), {'permits_url': lambda *a: True})())
    with sqlite3.connect(path) as conn:
        assert h.list_hypotheses(conn, TARGET)[0]['status'] == 'blocked'


def test_gap_key_and_evidence_context_include_hypothesis_dimensions():
    hunter = load_server('hunter')
    first = row()
    other = row(variant_id='another-control')
    assert hunter._coverage_context(first) != hunter._coverage_context(other)
    assert gap_plan(TARGET, {**first, 'endpoint': first['url']}, CONTEXT)[0] != gap_plan(TARGET, {**other, 'endpoint': other['url']}, CONTEXT)[0]
    base = {**first, 'endpoint': first['url']}
    assert gap_plan(TARGET, {**base, 'impact': 10}, CONTEXT)[0] == gap_plan(TARGET, base, CONTEXT)[0]


def test_ready_signal_validates_before_the_fuzz_batch_ends(monkeypatch):
    load_server('hunter')
    from cco_hunter_core.loop import execute_web_loop
    events = []
    item = row(vuln_class='sql_injection')
    def fuzz(*a, **kw):
        events.append('first-probe')
        publish_candidate(item)
        events.append('remaining-probes')
        return {'probes': 8, 'validator_queue': [item, item]}
    report = execute_web_loop(TARGET, live=True, crawl=False, max_validations=1,
        fuzz=fuzz, validate=lambda *a, **kw: events.append('validate') or {'verdict': 'INCONCLUSIVE'})
    assert events == ['first-probe', 'validate', 'remaining-probes']
    assert len(report['validations']) == len(report['validation_queue']) == 1
    assert report['budgets']['validations_used'] == 1


def test_streaming_uses_the_existing_real_fuzz_adapter(monkeypatch, tmp_path):
    hunter = load_server('hunter')
    from cco_hunter_core.loop import execute_web_loop
    from cco_surface_core.normalize import normalize_record
    records = [normalize_record({'url': TARGET + f'query{i}?q=apple', 'method': 'GET',
                                 'params': [{'name': 'q', 'in': 'query', 'sample': 'apple'}]}) for i in (1, 2)]
    for record in records:
        record['suggested_classes'] = ['sql_injection']
    monkeypatch.setattr(hunter, 'next_work', lambda *a, **kw: {'queue': records})
    monkeypatch.setattr(hunter, 'write_artifact', lambda *a, **kw: '')
    events = []
    def request(method, url, **kw):
        events.append('probe')
        return {'ok': True, 'status': 200, 'text': 'synthetic baseline', 'headers': {}}
    monkeypatch.setattr(hunter, '_live_request', request)
    monkeypatch.setattr(hunter, '_light_oracle', lambda *a: ('LIKELY', 'synthetic'))
    report = execute_web_loop(TARGET, live=True, crawl=False, sleep_s=0, fuzz=hunter._loop_fuzz,
                             validate=lambda *a, **kw: events.append('validate') or {'verdict': 'INCONCLUSIVE'})
    assert events.index('validate') == 2
    assert len(report['validations']) == 2


def test_listener_scope_does_not_leak_to_another_loop():
    events = []
    with candidate_listener(lambda item: events.append(item)):
        publish_candidate('one')
    publish_candidate('two')
    assert events == ['one']


def test_task_done_does_not_mark_hypothesis_confirmed(setup):
    hunter, runtime, campaign, *_ = setup
    item, ref = plan(hunter)
    schedule(runtime, campaign)
    task = runtime.claim_next_task('worker', campaign)
    assert task
    with sqlite3.connect(hunter.MEM_DB) as conn:
        states = h.list_hypotheses(conn, BASE)
    assert any(r['status'] == 'running' for r in states)
    runtime.complete_task_with_permit(task['execution_permit'], result={'ok': True}, actual_request_cost=0)
    with sqlite3.connect(hunter.MEM_DB) as conn:
        assert all(r['status'] not in h.TERMINAL for r in h.list_hypotheses(conn, BASE))


def test_signed_validation_closes_only_its_variant(setup):
    hunter, *_ = setup
    item = {'url': BASE + 'search?q=apple', 'method': 'GET', 'vuln_class': 'sql_injection',
            'identity': 'anonymous', 'resource_owner': 'unspecified', 'run_id': 'run-1', 'param': 'q',
            'carrier': 'query', **h.extensions(row())}
    other = {**item, **h.extensions(row(variant_id='other'))}
    assert hunter._record_coverage_plan(BASE, item) and hunter._record_coverage_plan(BASE, other)
    result = evidence(hunter, item, verdict='UNCONFIRMED')
    assert not hunter._record_coverage_validation(BASE, other, result)
    assert hunter._record_coverage_validation(BASE, item, result)
    with sqlite3.connect(hunter.MEM_DB) as conn:
        states = h.list_hypotheses(conn, BASE)
    assert len([r for r in states if r['status'] == 'tested_no_violation']) == 1
    assert len([r for r in states if r['status'] == 'ready']) == 1


def test_only_refreshed_identity_task_reopens(setup):
    hunter, runtime, campaign, *_ = setup
    bindings = json.loads(sessions(hunter))
    refs = [plan(hunter, identity=actor, run_id=actor + "-run")[1] for actor in ('alice', 'bob')]
    for actor in ('alice', 'bob'):
        schedule(runtime, campaign, session_bindings=json.dumps({actor: bindings[actor]}), run_id=actor + "-run")
    tasks = [runtime.claim_next_task('worker', campaign) for _ in refs]
    for task in tasks:
        args = json.loads(task['args_json'])
        block(runtime, campaign, args['gap_ref'], task=task)
    refresh(('alice',))
    resumed = runtime.resume_coverage_gaps(campaign, BASE)['resumed']
    assert len(resumed) == 1 and resumed[0]['gap_ref'] == refs[0]
    with sqlite3.connect(hunter.MEM_DB) as conn:
        states = {r['identity']: r['status'] for r in h.list_hypotheses(conn, BASE)}
    assert states == {'alice': 'ready', 'bob': 'blocked'}


def test_reporting_vector_success_does_not_close_other_operations(conn):
    one = h.observe(conn, TARGET, row(operation_id='orders'), CONTEXT)
    two = h.observe(conn, TARGET, row(operation_id='exports'), CONTEXT)
    assert h.complete(conn, one, {'status': 'confirmed', 'validation_id': 'receipt'}, lambda *a: True)
    states = {r['fingerprint']: r['status'] for r in h.list_hypotheses(conn, TARGET)}
    assert states[two] == 'proposed'


def test_forged_public_verdict_and_task_done_do_not_close_feedback(tmp_path):
    report = {'validations': [{**row(), 'verdict': 'CONFIRMED', 'coverage_recorded': True,
                               'validation_id': 'forged', 'task_status': 'done'}]}
    path = str(tmp_path / 'feedback.db')
    persisted = persist_feedback(path, TARGET, CONTEXT, report,
                                type('Scope', (), {'permits_url': lambda *a: True})())
    assert persisted[0]['status'] == 'inconclusive'
    with sqlite3.connect(path) as conn:
        assert h.list_hypotheses(conn, TARGET)[0]['status'] == 'inconclusive'


def test_early_owned_candidate_does_not_wait_for_crawl():
    load_server('hunter')
    from cco_hunter_core.loop import execute_web_loop
    url = TARGET + 'orders/owned-opaque'
    actors = {'alice': {'headers': {'Cookie': 'a'}, 'objects': [{'url': url, 'marker': 'owned'}]},
              'bob': {'headers': {'Cookie': 'b'}}}
    events = []
    execute_web_loop(TARGET, live=True, crawl=True, identities=actors,
        identity_discover=lambda *a: ({'status': 'ready', 'requests': 2}, actors,
                                      [{'url': url, 'vuln_class': 'bola', 'authz_candidate': True}]),
        authz_validate=lambda *a: events.append('validate') or {'verdict': 'INCONCLUSIVE'},
        crawl_fn=lambda *a, **kw: events.append('crawl') or {'ok': True})
    assert events == ['validate', 'crawl']


def test_ready_signal_priority_and_bounded_samples_remain_available():
    from cco_hunter_core.candidates import select_candidates
    signal = row(candidate_source='light_oracle')
    sample = row(vuln_class='ssti', candidate_source='bounded_sampling')
    assert fair_queue([sample, signal])[0] == signal
    candidate = {**row(vuln_class='ssti'), 'live': True, 'baseline_eligible': True,
                 'status': 200, 'coverage_status': 'inconclusive', 'triage_verdict': 'INCONCLUSIVE'}
    assert select_candidates([candidate], sample_limit=1)[0]['candidate_source'] == 'bounded_sampling'


def test_budget_deferred_variant_is_not_negative():
    load_server('hunter')
    from cco_hunter_core.loop import execute_web_loop
    report = execute_web_loop(TARGET, live=True, crawl=False, max_validations=0,
                              fuzz=lambda *a, **kw: {'probes': 1, 'validator_queue': [row(vuln_class='ssti')]})
    feedback = build_feedback(report)
    assert any(r['status'] == 'blocked' and r['reason_code'] == 'budget_exhausted' for r in feedback)
    assert not report['validations'] and report['budgets']['validations_used'] == 0


def test_brain_exposes_detailed_queue_without_vector_marking(tmp_path, capsys):
    import brain
    path = tmp_path / 'memory.db'
    with sqlite3.connect(path) as conn:
        h.observe(conn, TARGET, row(), CONTEXT)
    assert brain.main(['hypotheses', 'queue', '--db', str(path), '--target', TARGET]) == 0
    assert json.loads(capsys.readouterr().out)[0]['status'] == 'proposed'


@pytest.mark.parametrize('field', ['param', 'resource_family', 'operation_id'])
def test_nonstandard_field_names_do_not_collapse(field):
    assert h.dimension(TARGET, row(**{field: 'field one'}), CONTEXT)[0] != h.dimension(
        TARGET, row(**{field: 'field two'}), CONTEXT)[0]


def test_gap_root_and_nested_json_fields_stay_separate():
    first = {**row(), 'endpoint': row()['url'], 'param': '$body'}
    second = {**first, 'param': 'items[0]'}
    assert gap_plan(TARGET, first, CONTEXT)[0] != gap_plan(TARGET, second, CONTEXT)[0]


def test_exhausted_campaign_budget_blocks_the_exact_hypothesis(setup):
    hunter, runtime, campaign, *_ = setup
    plan(hunter, run_id='first')
    runtime.schedule_coverage_gaps(campaign, BASE, request_cost=24, run_id='first',
                                   headers=json.dumps({'X-Research': 'researcher'}))
    item, _ = plan(hunter, run_id='second', param='sort')
    deferred = runtime.schedule_coverage_gaps(campaign, BASE, request_cost=4, run_id='second',
                                               headers=json.dumps({'X-Research': 'researcher'}))['deferred']
    assert deferred and 'budget' in deferred[0]['reason']
    with sqlite3.connect(hunter.MEM_DB) as conn:
        second = [r for r in h.list_hypotheses(conn, BASE) if r['run_id'] == 'second']
    assert len(second) == 1 and second[0]['status'] == 'blocked' and second[0]['reason'] == 'budget_exhausted'


def test_lost_verified_evidence_downgrades_cached_terminal(tmp_path):
    path = str(tmp_path / 'feedback.db')
    item = {**row(), 'validation_id': 'receipt-1'}
    scope = type('Scope', (), {'permits_url': lambda *a: True})()
    report = {'validations': [item]}
    trusted = [{**item, 'status': 'confirmed'}]
    persisted = persist_feedback(path, TARGET, CONTEXT, report, scope, trusted)
    assert persisted[0]['status'] == 'confirmed'
    persist_feedback(path, TARGET, CONTEXT, report, scope, [])
    with sqlite3.connect(path) as conn:
        assert all(r['status'] == 'inconclusive' for r in h.list_hypotheses(conn, TARGET))
