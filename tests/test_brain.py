"""E1 task selection and E2 crash/restart contracts; owned local fixtures only."""
from __future__ import annotations

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace
from urllib.request import urlopen

import pytest

import brain
from campaign_runtime import CampaignRuntime
from full_agent_broker import dump
from full_agent_budget import SharedBudget
from full_agent_python_broker import PythonBroker
from full_agent_python_solver import PythonSolver
from full_agent_tasks import NativeTasks
from test_full_agent_python_solver import python_broker, terminal
from workflow_checkpoint import WorkflowCheckpoint


def registry(broker, *ids):
    template = broker.tasks.specs[0]
    specs = []
    for ident in ids:
        spec = copy.deepcopy(template)
        spec.id, spec.evidence_dir, spec.depends_on = ident, str(broker.workdir / ident), []
        specs.append(spec)
    broker.tasks = NativeTasks(specs, broker.workdir, {})
    return broker.tasks.specs


def finish(solver, spec):
    summary = solver.compile_summary(spec, terminal(spec))
    path = solver.broker.tasks.summary_path(spec)
    path.parent.mkdir(exist_ok=True)
    dump(path, summary)
    solver.summaries[spec.id] = summary
    return summary


def fresh_budget(broker):
    broker.budget = SharedBudget(http=300, tokens=150000, seconds=900)
    broker.runtime_policy.budget = broker.budget


def test_blocked_prerequisite_does_not_stop_independent_task(python_broker, monkeypatch):
    first, child, independent = registry(python_broker, 'needs-session', 'dependent', 'independent')
    child.depends_on = [first.id]
    solver = PythonSolver(python_broker, model='model')
    calls = []
    def phase(spec):
        calls.append(spec.id)
        summary = finish(solver, spec)
        if spec.id == first.id:
            summary['status'] = 'blocked'
            dump(python_broker.tasks.summary_path(spec), summary)
        return summary
    monkeypatch.setattr(solver, 'phase', phase)
    result = solver.run()
    assert calls == ['needs-session', 'independent']
    assert result['task_states'] == {'needs-session': 'blocked', 'independent': 'completed', 'dependent': 'blocked'}
    assert result['closure_verified'] is False


def test_missing_handoff_blocks_only_that_task(python_broker, monkeypatch):
    access, independent = registry(python_broker, 'needs-handoff', 'independent')
    access.phase = 'access'
    solver = PythonSolver(python_broker, model='model')
    calls = []
    monkeypatch.setattr(solver, 'phase', lambda task: calls.append(task.id) or finish(solver, task))
    result = solver.run()
    assert calls == [independent.id]
    assert result['task_states'][access.id] == 'blocked'
    assert not python_broker.executor.tasks


def observe(db, target, *, identity='anon', param='q', context='authorized-v1'):
    import hypothesis_ledger
    hypothesis_ledger.observation_queue(db, target)  # load surface module without any traffic
    from cco_surface_core import hypotheses as h
    with sqlite3.connect(db) as conn:
        return h.observe(conn, target, {'url': target + '?q=owned', 'method': 'GET',
            'operation_id': 'owned-search', 'param': param, 'carrier': 'query', 'identity': identity,
            'vuln_class': 'sql_injection', 'run_id': 'owned-run', 'observation_id': 1}, context)


def test_p5_new_observation_opens_task_missing_session_does_not_block_plan(python_broker, tmp_path, monkeypatch):
    spec, = registry(python_broker, 'discover')
    spec.tools.append('hunter_run_web_loop')
    db = tmp_path / 'observations.db'
    missing = observe(db, spec.target, identity='missing-owned-session')
    ready = observe(db, spec.target)
    solver = PythonSolver(python_broker, model='model', observed_db=db, observation_context='authorized-v1')
    calls, new = [], []
    def phase(task):
        calls.append(task.id)
        if task.references and not new:
            new.append(observe(db, spec.target, param='sort'))
        return finish(solver, task)
    monkeypatch.setattr(solver, 'phase', phase)
    result = solver.run()
    assert calls == ['discover', 'operation-' + ready, 'operation-' + new[0]]
    assert result['task_states']['operation-' + missing] == 'blocked'
    assert all(set(task.tools) <= set(spec.tools) and task.target == spec.target
               for task in python_broker.tasks.specs)
    assert not python_broker.executor.tasks


def test_observation_selection_cannot_grant_tools_or_other_context(python_broker, tmp_path):
    spec, = registry(python_broker, 'discover')
    db = tmp_path / 'observations.db'
    observe(db, spec.target)
    solver = PythonSolver(python_broker, model='model', observed_db=db, observation_context='authorized-v1')
    solver.refresh_observed_specs()
    assert len(python_broker.tasks.specs) == 1  # no hunter permission in original envelope
    spec.tools.append('hunter_run_web_loop')
    solver = PythonSolver(python_broker, model='model', observed_db=db, observation_context='unapproved-context')
    solver.refresh_observed_specs()
    assert len(python_broker.tasks.specs) == 1


@pytest.mark.parametrize('args', [{'live': True}, {'target': 'https://outside.invalid/', 'live': False}])
def test_p5_plan_never_admits_live_requests(python_broker, tmp_path, args):
    spec, = registry(python_broker, 'discover')
    spec.tools.append('hunter_run_web_loop')
    db = tmp_path / 'observations.db'
    observe(db, spec.target)
    solver = PythonSolver(python_broker, model='model', observed_db=db)
    solver.refresh_observed_specs()
    python_broker.tasks.active_spec = python_broker.tasks.specs[-1]
    with pytest.raises(ValueError, match='planning only'):
        python_broker.invoke('hunter_run_web_loop', args)
    assert not python_broker.executor.tasks and python_broker.budget.used['http'] == 0


def test_p5_phase_runs_without_lab_handoff_or_implicit_validator(python_broker, tmp_path, monkeypatch):
    spec, = registry(python_broker, 'discover')
    spec.tools.append('hunter_run_web_loop')
    db = tmp_path / 'observations.db'
    observe(db, spec.target)
    solver = PythonSolver(python_broker, model='model', observed_db=db)
    solver.refresh_observed_specs()
    task = python_broker.tasks.specs[-1]
    python_broker.catalog['hunter'] = [{'name': 'run_web_loop', 'inputSchema': {'type': 'object',
        'properties': {'target': {'type': 'string'}, 'live': {'type': 'boolean'}}}}]
    calls = []
    def execute(_self, request):
        args = json.loads(request['args_json'])
        calls.append(args)
        assert args['live'] is False and args['target'] == task.target
        return {'actual_request_cost': 0, 'result': {'output': {'mode': 'PLAN_ONLY', 'ok': True}}}
    monkeypatch.setattr(type(python_broker.executor), '__call__', execute)
    def completion(body):
        context = json.loads(body['messages'][1]['content'])
        assert context['planning_only'] and context['handoff'] is None
        assert context['task_spec']['references'] == task.references
        if not calls:
            return {'choices': [{'message': {'tool_calls': [{'function': {'name': 'hunter_run_web_loop',
                'arguments': json.dumps({'target': task.target, 'live': False})}}]}}]}
        return {'choices': [{'message': {'content': json.dumps(terminal(task))}}]}
    monkeypatch.setattr(python_broker, 'completion', completion)
    assert solver.phase(task)['status'] == 'done'
    assert len(calls) == 1 and python_broker.budget.used['http'] == 0


def test_dynamic_registry_resume_preserves_completed_p5_tasks(python_broker, tmp_path, monkeypatch):
    spec, = registry(python_broker, 'discover')
    spec.tools.append('hunter_run_web_loop')
    db = tmp_path / 'observations.db'
    first = observe(db, spec.target)
    solver = PythonSolver(python_broker, model='model', observed_db=db)
    monkeypatch.setattr(solver, 'phase', lambda task: finish(solver, task))
    assert solver.run()['status'] == 'python_tasks_finished'
    new = observe(db, spec.target, param='sort')
    fresh_budget(python_broker)
    resumed = PythonSolver(python_broker, model='model', observed_db=db, resume=True)
    calls = []
    monkeypatch.setattr(resumed, 'phase', lambda task: calls.append(task.id) or finish(resumed, task))
    result = resumed.run()
    assert result['status'] == 'python_tasks_finished'
    assert calls == ['operation-' + new]
    assert result['task_states']['operation-' + first] == 'completed'


def test_completed_checkpoint_skips_all_requests_and_reconciles_budget(python_broker, monkeypatch):
    spec, = registry(python_broker, 'owned-fetch')
    solver = PythonSolver(python_broker, model='model')
    def phase(task):
        python_broker.invoke('kali-tools_curl_request', {'url': task.target})
        return finish(solver, task)
    monkeypatch.setattr(solver, 'phase', phase)
    assert solver.run()['status'] == 'python_tasks_finished'
    assert len(python_broker.executor.tasks) == 1
    fresh_budget(python_broker)
    resumed = PythonSolver(python_broker, model='model', resume=True)
    monkeypatch.setattr(resumed, 'phase', lambda *_a: pytest.fail('completed phase replayed'))
    result = resumed.run()
    assert result['status'] == 'python_tasks_finished'
    assert result['budget']['used']['http'] == 1 and len(python_broker.executor.tasks) == 1
    # Repeated resumes do not recharge settled usage or reset elapsed time.
    previous = result['budget']['remaining_seconds']
    fresh_budget(python_broker)
    result = PythonSolver(python_broker, model='model', resume=True).run()
    assert result['budget']['used']['http'] == 1 and result['budget']['remaining_seconds'] <= previous


@pytest.mark.parametrize('tamper', ['artifact', 'signature', 'policy', 'bindings', 'budget', 'symlink'])
def test_resume_rejects_changed_evidence_or_authority_before_execution(python_broker, monkeypatch, tmp_path, tamper):
    spec, = registry(python_broker, 'owned-fetch')
    policy = tmp_path / 'scope.json'
    policy.write_text('{"owned":true}')
    python_broker.engine.scope_file = policy
    solver = PythonSolver(python_broker, model='model')
    monkeypatch.setattr(solver, 'phase', lambda task: finish(solver, task))
    solver.run()
    checkpoint = python_broker.workdir / 'checkpoint.json'
    if tamper == 'artifact':
        python_broker.tasks.summary_path(spec).write_text('{}')
    elif tamper == 'signature':
        data = json.loads(checkpoint.read_text())
        data['payload']['budget']['used']['http'] = 0
        data['signature'] = '00' * 64
        checkpoint.write_text(json.dumps(data))
    elif tamper == 'policy':
        policy.write_text('{"owned":false}')
    elif tamper == 'bindings':
        python_broker.tasks.bindings['unapproved'] = {'target': spec.target}
    elif tamper == 'symlink':
        original = checkpoint.read_bytes()
        checkpoint.unlink()
        other = tmp_path / 'other.json'
        other.write_bytes(original)
        checkpoint.symlink_to(other)
    fresh_budget(python_broker)
    if tamper == 'budget':
        python_broker.budget.limits['http'] = 301
    resumed = PythonSolver(python_broker, model='model', resume=True)
    monkeypatch.setattr(resumed, 'phase', lambda *_a: pytest.fail('invalid checkpoint executed'))
    assert resumed.run()['status'] == 'python_failed'
    assert not python_broker.executor.tasks


@pytest.mark.parametrize('point', ['before_tool_return', 'after_tool_return', 'pending_tokens', 'ctrl_c'])
@pytest.mark.integration
def test_interrupted_dispatch_is_never_replayed(python_broker, monkeypatch, point):
    """SIGKILL the real solver around a counted loopback HTTP request."""
    class Handler(BaseHTTPRequestHandler):
        count = 0
        def do_GET(self):
            type(self).count += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'owned synthetic response')
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        first, dependent, independent = registry(python_broker, 'interrupted', 'dependent', 'independent')
        dependent.depends_on = [first.id]
        for spec in python_broker.tasks.specs:
            spec.target = f'http://127.0.0.1:{server.server_port}/'
        contract = python_broker.workdir.parent / 'crash-contract.json'
        dump(contract, {'point': point, 'workdir': str(python_broker.workdir),
                        'private': str(python_broker.private),
                        'specs': [spec.to_dict() for spec in python_broker.tasks.specs]})
        env = {**os.environ, 'PYTHONPATH': os.pathsep.join([
            str(Path(__file__).resolve().parents[1] / 'scripts'), str(Path(__file__).resolve().parent)])}
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), str(contract)],
                               env=env, capture_output=True, timeout=30)
        assert child.returncode == (0 if point == 'ctrl_c' else -signal.SIGKILL), child.stderr.decode()
        payload = WorkflowCheckpoint(python_broker.workdir).read()
        assert payload['task_states'][first.id] == 'running'
        fresh_budget(python_broker)
        resumed = PythonSolver(python_broker, model='model', resume=True)
        calls = []
        monkeypatch.setattr(resumed, 'phase', lambda task: calls.append(task.id) or finish(resumed, task))
        result = resumed.run()
        assert calls == [independent.id]
        assert result['task_states'][first.id] == 'inconclusive'
        assert result['task_states'][dependent.id] == 'blocked'
        assert Handler.count == (0 if point == 'pending_tokens' else 1)
        assert result['budget']['used']['http'] == (300 if point == 'before_tool_return' else
                                                   0 if point == 'pending_tokens' else 1)
        assert result['budget']['used']['tokens'] == (17 if point == 'pending_tokens' else 0)
        fresh_budget(python_broker)
        second_resume = PythonSolver(python_broker, model='model', resume=True).run()
        assert second_resume['budget']['used'] == result['budget']['used']
        assert Handler.count == (0 if point == 'pending_tokens' else 1)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_exclusive_checkpoint_lock_and_existing_run_refuse_reexecution(python_broker, monkeypatch):
    registry(python_broker, 'owned-fetch')
    lock = WorkflowCheckpoint(python_broker.workdir)
    lock.acquire()
    try:
        solver = PythonSolver(python_broker, model='model')
        monkeypatch.setattr(solver, 'phase', lambda *_a: pytest.fail('concurrent execution'))
        assert solver.run()['status'] == 'python_failed'
    finally:
        lock.release()
    solver = PythonSolver(python_broker, model='model')
    monkeypatch.setattr(solver, 'phase', lambda task: finish(solver, task))
    solver.run()
    second = PythonSolver(python_broker, model='model')
    monkeypatch.setattr(second, 'phase', lambda *_a: pytest.fail('implicit replay'))
    assert second.run()['status'] == 'python_failed'


def test_campaign_uses_canonical_checkpoint_and_checks_latest_integrity(python_broker, monkeypatch):
    registry(python_broker, 'owned-fetch')
    solver = PythonSolver(python_broker, model='model')
    monkeypatch.setattr(solver, 'phase', lambda task: finish(solver, task))
    solver.run()
    runtime = CampaignRuntime(str(python_broker.private / 'state'))
    campaign = runtime.create_campaign('owned-fixture')
    goal = {'endpoint': python_broker.tasks.specs[0].target, 'requires': []}
    runtime.store_campaign_checkpoint(campaign, {'goal': goal, 'operator_notes': 'owned fixture'})
    payload = runtime.bind_solver_checkpoint(campaign, python_broker.workdir)
    conn = runtime._connect()
    try:
        control = runtime._read_checkpoint_locked(conn, campaign)
        assert control['goal'] == goal and control['operator_notes'] == 'owned fixture'
        assert control['solver_checkpoint']['run_id'] == payload['run_id']
    finally:
        conn.close()
    assert runtime.read_solver_checkpoint(campaign)['run_id'] == payload['run_id']
    python_broker.tasks.summary_path(python_broker.tasks.specs[0]).write_text('{}')
    with pytest.raises(ValueError, match='integrity'):
        runtime.read_solver_checkpoint(campaign)


def test_interrupted_atomic_replace_retains_latest_valid_checkpoint(python_broker, monkeypatch):
    import evidence_trust
    registry(python_broker, 'owned-fetch')
    solver = PythonSolver(python_broker, model='model')
    monkeypatch.setattr(solver, 'phase', lambda task: finish(solver, task))
    solver.run()
    checkpoint = WorkflowCheckpoint(python_broker.workdir)
    original = checkpoint.path.read_bytes()
    payload = checkpoint.read()
    checkpoint.acquire()
    try:
        def interrupted_replace(*_args):
            raise OSError('synthetic interruption before atomic replace')
        monkeypatch.setattr(evidence_trust.os, 'replace', interrupted_replace)
        with pytest.raises(OSError):
            checkpoint.write({**payload, 'run_id': 'never-committed'})
        assert checkpoint.path.read_bytes() == original
        assert checkpoint.read()['run_id'] == payload['run_id']
        assert not list(python_broker.workdir.glob('.evidence-*.tmp'))
    finally:
        checkpoint.release()


def test_brain_observed_specs_remain_planning_only(python_broker, tmp_path):
    db = tmp_path / 'observations.db'
    spec, = registry(python_broker, 'owned-fetch')
    key = observe(db, spec.target)
    planned, = brain.observed_specs(db, spec.target, tmp_path, 'authorized-v1')
    assert planned.id == 'operation-' + key
    assert 'live=false' in planned.commands[0]


def crash_worker(contract):
    from orchestration_spec import TaskSpec
    data = json.loads(Path(contract).read_bytes())
    point = data['point']
    class Executor:
        timeout_seconds = 900
        def __call__(self, task):
            with urlopen(json.loads(task['args_json'])['url'], timeout=5) as response:
                assert response.status == 200
            if point == 'before_tool_return':
                os.kill(os.getpid(), signal.SIGKILL)
            return {'actual_request_cost': 1, 'result': {'output': {'ok': True}}}
        def terminate(self):
            pass
    engine = SimpleNamespace(_is_known_tool=lambda _name: True,
        _rate_limit_for=lambda _name: (0, 60),
        tool_capability=lambda name: {'network': name == 'kali-tools_curl_request'},
        validate_tool_invocation=lambda *_a, **_kw: {'allowed': True, 'reason': 'owned fixture'})
    broker = PythonBroker(budget=SharedBudget(http=300, tokens=150000, seconds=900), engine=engine,
                          executor=Executor(), workdir=Path(data['workdir']), private=Path(data['private']),
                          provider='https://provider.invalid/v1', models={'model'}, api_key='host-only-sentinel')
    broker.tasks = NativeTasks([TaskSpec.from_dict(spec) for spec in data['specs']], broker.workdir, {})
    solver = PythonSolver(broker, model='model')
    def phase(spec):
        if point == 'pending_tokens':
            broker.budget.reserve('tokens', 17)
        else:
            broker.invoke('kali-tools_curl_request', {'url': spec.target})
        if point == 'ctrl_c':
            raise KeyboardInterrupt
        os.kill(os.getpid(), signal.SIGKILL)
    solver.phase = phase
    try:
        solver.run()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    crash_worker(sys.argv[1])
