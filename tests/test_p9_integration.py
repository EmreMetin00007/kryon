"""Socket-free P9 orchestration, exact reference, outcome and operator contracts."""
import copy
import json
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for part in ('scripts', 'mcp-servers/mcp-memory-server', 'mcp-servers/mcp-hunter'):
    sys.path.insert(0, str(ROOT / part))
from agent_integration import preflight, references, normalize_outcome, validate_references
from orchestration_spec import TaskSpec, render_task_prompt
from brain import observed_specs, next_spec
from campaign_runtime import CampaignRuntime
from campaign_worker import CampaignWorker, ChainTaskExecutor
from cco_surface_core import hypotheses as h
from tui_snapshot import campaign_snapshot
from test_campaign_gap_bridge import setup as gap_setup, plan, schedule, BASE
from test_p8_chaining import setup as chain_setup, ReadLab, Gate, PRODUCER
from workflow_compiler import compile_evidence_chain


def candidate(**changes):
    return {'url': 'https://p9.test/api/orders/own?q=baseline', 'method': 'GET',
            'operation_id': 'orders-detail', 'carrier': 'query', 'param': 'q',
            'identity': 'alice', 'resource_owner': 'bob', 'resource_id': 'synthetic-own',
            'request_state': {'view': 'details'}, 'variant_id': 'control-v1',
            'vuln_class': 'bola', 'observation_id': 1, 'run_id': 'run-p9', **changes}


def spec(**changes):
    return TaskSpec(id='access-1', phase='access', target='https://p9.test/',
                    evidence_dir='/tmp/cco-work/p9-test/access',
                    tools=['kali-tools_curl_request'], commands=['Fetch observed resource'], **changes)


@pytest.mark.parametrize('compact', [False, True])
def test_references_survive_serialization_and_prompt(compact):
    key, dimension = h.dimension('https://p9.test/', candidate(), 'context-p9')
    refs = references({'fingerprint': key, 'dimension': dimension})
    task = TaskSpec.from_dict(spec(references=refs).to_dict())
    if compact:
        task.tool_profile = 'broker'
    prompt = render_task_prompt(task, compact=compact, scaffolded=compact)
    assert task.references == refs and key in prompt and 'orders-detail' in prompt
    assert not validate_references(refs)


@pytest.mark.parametrize('field,value', [('operation_id', 'export'), ('identity', 'carol'),
    ('resource_owner', 'dana'), ('resource_id', 'other'), ('request_state', {'view': 'download'}),
    ('variant_id', 'control-v2'), ('vuln_class', 'bfla'), ('param', 'sort'),
    ('carrier', 'body'), ('method', 'POST'), ('run_id', 'other'), ('observation_id', 2)])
def test_brain_preserves_every_independent_dimension(tmp_path, field, value):
    db = tmp_path / 'agent_memory.db'
    with sqlite3.connect(db) as conn:
        one = h.observe(conn, 'https://p9.test/', candidate(), 'context-p9')
        two = h.observe(conn, 'https://p9.test/', candidate(**{field: value}), 'context-p9')
    plans = observed_specs(db, 'https://p9.test/', tmp_path, 'context-p9')
    assert {p.references['hypothesis_ref'] for p in plans} == {one, two}
    assert all(preflight(p)['status'] == 'ready' for p in plans)


@pytest.mark.parametrize('field', ['hypothesis_ref', 'operation_ref', 'dimension'])
def test_reference_edits_fail_local_validation(field):
    key, dimension = h.dimension('https://p9.test/', candidate(), 'context-p9')
    refs = references({'fingerprint': key, 'dimension': dimension})
    refs[field] = {} if field == 'dimension' else 'edited'
    result = preflight(spec(references=refs))
    assert result['status'] == 'blocked' and result['reason_code'] == 'schema_validation_failed'


def test_structured_repair_runs_once_and_preserves_input():
    task = spec()
    task.id = ''
    called = []
    def fix(detached, feedback):
        called.append(feedback)
        detached.commands = ['better syntax']
        return detached
    result = preflight(task, fix)
    assert result['status'] == 'blocked' and result['repair_attempts'] == len(called) == 1
    assert task.commands == ['Fetch observed resource']


def test_single_repair_can_fix_step_schema():
    from orchestration_spec import Step
    task = spec()
    task.steps = [Step(id='fetch', command='')]
    def fix(detached, feedback):
        detached.steps[0].command = 'Fetch the already observed resource'
        return detached
    result = preflight(task, fix)
    assert result['status'] == 'ready' and result['repair_attempts'] == 1
    assert task.steps[0].command == ''


@pytest.mark.parametrize('field,value', [('target', 'https://outside.invalid/'), ('scope_ref', '/tmp/other'),
    ('max_calls', 30), ('max_minutes', 30), ('tools', ['kali-tools_nmap_scan']),
    ('evidence_dir', '/tmp/foreign'), ('depends_on', ['foreign']), ('tool_profile', 'broker')])
def test_repair_cannot_change_authority(field, value):
    task = spec()
    task.id = ''
    def fix(detached, feedback):
        setattr(detached, field, value)
        return detached
    result = preflight(task, fix)
    assert result['status'] == 'blocked' and result['errors'] == ['repair changed execution authority']


def test_invalid_chain_stops_before_dispatch():
    task = spec()
    task.tools = []
    dispatch, reason = next_spec([task], {})
    assert dispatch is None and 'invalid spec chain' in reason


@pytest.mark.parametrize('tool', ['hunter_run_web_loop', 'chain_runner_execute'])
@pytest.mark.parametrize('raw', [{'verdict': 'CONFIRMED', 'success': True, 'reportable': True},
    {'output': '{"verdict":"CONFIRMED","scope_completion":"complete"}'},
    {'executed': False, 'mode': 'dry_run'}])
def test_common_outcome_does_not_trust_claims(tool, raw):
    out = normalize_outcome({'tool_name': tool}, raw, status='done', requests_sent=0)
    assert out['schema'] == 'agent-outcome/1' and out['test_result'] == 'inconclusive'
    assert not out['reportable'] and out['run_closure'] == 'open' and out['scope_completion'] == 'incomplete'


@pytest.mark.parametrize('usage', [-1, True, 1.2, '2', None])
def test_outcome_requires_measured_integer(usage):
    with pytest.raises(ValueError):
        normalize_outcome({}, {}, status='done', requests_sent=usage)


def test_campaign_scheduler_and_brain_use_identical_p5_references(gap_setup, tmp_path):
    hunter, runtime, campaign, *_ = gap_setup
    plan(hunter)
    assert schedule(runtime, campaign)['scheduled']
    task, = runtime.list_tasks(campaign)
    refs = json.loads(task['references_json'])
    plans = observed_specs(hunter.MEM_DB, BASE, tmp_path)
    assert refs in [p.references for p in plans]
    assert refs['hypothesis_ref'] != json.loads(task['args_json'])['gap_ref']
    result = runtime.enqueue_spec(campaign, next(p for p in plans if p.references == refs),
        json.loads(task['args_json']), tool_name='hunter_run_web_loop', request_cost=4)
    assert result['task_id'] == task['id']


def test_missing_session_is_not_a_contract_repair(gap_setup):
    hunter, runtime, campaign, *_ = gap_setup
    plan(hunter, identity='alice')
    result = schedule(runtime, campaign)
    assert not result['scheduled'] and result['deferred']
    assert runtime.list_tasks(campaign) == []


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    scope = tmp_path / 'scope.json'
    policy = tmp_path / 'policy.json'
    scope.write_text(json.dumps({'in_scope': [{'asset': 'https://p9.test/'}]}))
    policy.write_text('{}')
    monkeypatch.setenv('CCO_SCOPE_FILE', str(scope))
    monkeypatch.setenv('CCO_PROGRAM_POLICY_FILE', str(policy))
    monkeypatch.setenv('CCO_HOME', str(home))
    runtime = CampaignRuntime(str(home))
    return runtime


def test_budget_deferred_work_and_evidence_survive_restart(runtime):
    campaign = runtime.create_campaign('p9', budget_requests=2)
    first = runtime.enqueue_task(campaign, 'local', '', {'target': 'https://p9.test/'}, request_cost=2)
    runtime.enqueue_task(campaign, 'local', '', {'target': 'https://p9.test/'}, request_cost=1)
    worker = CampaignWorker(runtime, 'offline', lambda _: {'result': {'artifact': 'fixture:first-proof'}, 'actual_request_cost': 2})
    assert worker.run_once(campaign)['status'] == 'done'
    assert worker.run_once(campaign) == {'claimed': False}
    runtime = CampaignRuntime(str(runtime.cco_home))
    tasks = runtime.list_tasks(campaign)
    assert next(t for t in tasks if t['id'] == first)['status'] == 'done'
    assert json.loads(next(t for t in tasks if t['id'] == first)['result_json'])['outcome']['artifacts']
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['requests_sent'] == snap['requests_charged'] == 2 and snap['requests_remaining'] == 0
    assert snap['budget_exhausted'] and snap['task_completion'] == 'incomplete'
    assert snap['remaining'][0]['reason'] == 'blocked_budget'
    assert not runtime.check_close_out(campaign)['ok']
    closed = runtime.close_out(campaign, waive_untested='budget exhausted; preserve the remaining task')
    assert closed['closed']
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['run_closure'] == 'closed' and snap['scope_completion'] == 'incomplete'
    assert closed['close_out']['integration']['remaining'] == snap['remaining']


def test_empty_queue_never_proves_scope_complete(runtime):
    campaign = runtime.create_campaign('empty')
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['task_completion'] == 'incomplete' and snap['scope_completion'] == 'incomplete'
    assert snap['requests_remaining'] is None


@pytest.mark.parametrize('safe', [False, True])
def test_socketless_campaign_p8_twins_and_durable_replay(chain_setup, tmp_path, monkeypatch, safe):
    s = chain_setup
    monkeypatch.setenv('CCO_WORKDIR', str(tmp_path / 'work'))
    monkeypatch.setenv('CCO_GRAPH_BACKEND', 'networkx')
    policy = tmp_path / 'policy.json'
    policy.write_text('{}')
    monkeypatch.setenv('CCO_PROGRAM_POLICY_FILE', str(policy))
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'in_scope': [{'asset': 'https://p8.test/'}]}))
    monkeypatch.setenv('CCO_SCOPE_FILE', str(scope))
    runtime = CampaignRuntime(str(tmp_path / 'home'))
    runtime._policy_engine(str(scope)).grant_approval('chain_runner_*', 'p8.test', ttl_seconds=600, reason='offline synthetic handler')
    campaign = runtime.create_campaign('twins', scope_file=str(scope), budget_requests=4)
    manifest = compile_evidence_chain(s['graph'], s['spec'])['manifest']
    runtime.enqueue_task(campaign, 'chain', 'chain_runner_execute', {'url': PRODUCER,
        'manifest': manifest, 'identities': s['identities']}, request_cost=4)
    lab = ReadLab(safe=safe)
    worker = CampaignWorker(runtime, 'offline', chain_executor=ChainTaskExecutor(runtime,
        sender=lab.sender, policy_engine=Gate(), evidence_graph=s['graph'], evidence_context=s['runtime']))
    assert worker.run_once(campaign)['status'] == 'done'
    task, = runtime.list_tasks(campaign)
    result = json.loads(task['result_json'])
    assert result['verdict'] == ('NOT_CONFIRMED' if safe else 'CONFIRMED')
    assert len(lab.calls) == result['outcome']['requests_sent'] == 4
    assert not result['outcome']['reportable'] and result['outcome']['test_result'] == 'inconclusive'
    replay = result['replay_evidence_hash']
    from evidence_chaining import EvidenceGraph
    with_graph = EvidenceGraph(s['graph'].db.execute('PRAGMA database_list').fetchone()[2], clock=lambda: 1000.0)
    try:
        assert with_graph.replay(replay)['verdict'] == result['verdict']
    finally:
        with_graph.close()
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['task_completion'] == 'done' and snap['run_closure'] == 'open'
    assert snap['scope_completion'] == 'incomplete' and snap['requests_remaining'] == 0
    for name, value in [('outcome', result), ('manifest', manifest), ('snapshot', snap),
                        ('replay', s['graph'].replay(replay))]:
        (tmp_path / (name + '.json')).write_text(json.dumps(value, indent=2))


def test_hud_rechecks_signed_clean_result_and_stale_policy(gap_setup, tmp_path):
    from test_campaign_gap_bridge import evidence
    hunter, runtime, campaign, _scope, policy = gap_setup
    item = {'url': BASE + 'search?q=apple', 'method': 'GET', 'vuln_class': 'sql_injection',
            'identity': 'anonymous', 'resource_owner': 'unspecified', 'run_id': 'run-1', 'param': 'q', 'carrier': 'query'}
    assert hunter._record_coverage_plan(BASE, item)
    result = evidence(hunter, item, verdict='UNCONFIRMED')
    assert hunter._record_coverage_validation(BASE, item, result)
    runtime.enqueue_task(campaign, 'local', '', {'target': BASE}, request_cost=0)
    worker = CampaignWorker(runtime, 'offline', lambda _: {'result': {'ok': True}, 'actual_request_cost': 0})
    assert worker.run_once(campaign)['status'] == 'done'
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['tested'] == 1 and snap['confirmed'] == 0, snap
    policy.write_text(json.dumps({'required_request_headers': {'X-Changed': 'new'}}))
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['tested'] == snap['confirmed'] == 0


def test_hud_limits_task_counts_to_selected_campaign(runtime):
    one, two = runtime.create_campaign('one'), runtime.create_campaign('two')
    runtime.enqueue_task(one, 'local', '', {}, request_cost=0)
    assert campaign_snapshot(runtime.cco_home, one)['tasks_by_status'] == {'pending': 1}
    assert campaign_snapshot(runtime.cco_home, two)['tasks_by_status'] == {}


def test_invalid_spec_is_blocked_before_queue_and_policy(runtime):
    campaign = runtime.create_campaign('invalid')
    task = spec()
    task.max_calls = 100
    result = runtime.enqueue_spec(campaign, task, {'target': task.target}, tool_name=task.tools[0])
    assert result['reason_code'] == 'schema_validation_failed'
    assert runtime.list_tasks(campaign) == []


def test_unknown_usage_is_charged_without_inventing_sent_requests(runtime):
    campaign = runtime.create_campaign('unknown', budget_requests=3)
    runtime.enqueue_task(campaign, 'local', '', {}, request_cost=3)
    task = runtime.claim_next_task('offline', campaign)
    runtime.block_task_with_permit(task['execution_permit'], 'count unavailable', result={'artifact': 'fixture:partial'})
    stored = json.loads(runtime.list_tasks(campaign)[0]['result_json'])['outcome']
    assert not stored['request_count_known'] and stored['requests_sent'] == 0 and stored['requests_charged'] == 3
    snap = campaign_snapshot(runtime.cco_home, campaign)
    assert snap['requests_charged'] == 3 and not snap['request_count_known']


def test_solver_invalid_contract_never_calls_provider(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from full_agent_python_solver import PythonSolver, WorkflowError
    solver = object.__new__(PythonSolver)
    solver.broker = SimpleNamespace(completion=lambda *_: pytest.fail('provider called on invalid contract'))
    task = spec()
    task.tools = []
    with pytest.raises(WorkflowError) as failure:
        solver.phase(task)
    assert failure.value.code == 'schema_validation_failed'
