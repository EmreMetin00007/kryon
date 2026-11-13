"""Local Python engine harness for compiled P7/P8 manifest acceptance."""
import json
from urllib.parse import urlsplit

from full_agent_budget import SharedBudget
from full_agent_python_broker import PythonBroker
from full_agent_python_solver import PythonSolver
from full_agent_tasks import NativeTasks
from orchestration_spec import COMPILED_WORKFLOW_TOOL, Step, TaskSpec
from policy_engine import PolicyEngine


def workflow_engine(tmp_path, monkeypatch, target, identities, sender=None):
    work, private, home = (tmp_path / name for name in ('workflow', 'private', 'home'))
    for path in (work, private, home):
        path.mkdir(exist_ok=True)
    monkeypatch.setenv('CCO_HOME', str(home))
    monkeypatch.delenv('CCO_EVIDENCE_PUBLIC_ONLY', raising=False)
    monkeypatch.delenv('CCO_EVIDENCE_TRUST_FILE', raising=False)
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'scope_policy': 'explicit_only', 'allow_loopback': True,
                                'in_scope': [{'asset': target, 'type': 'web'}]}))
    policy = tmp_path / 'program.json'
    policy.write_text(json.dumps({'profile': 'e4-local', 'allow_loopback': True,
        'rate_limits': {'default': {'window_seconds': 60, 'max_calls': 60}}}))
    engine = PolicyEngine(cco_home=str(home), scope_file=str(scope), program_policy_file=str(policy))
    engine.permissions_file.write_text(json.dumps(engine.permissions))
    engine.grant_approval('chain_runner_*', urlsplit(target).hostname, ttl_seconds=600,
                          reason='authorized E4 synthetic fixture; exact scope still applies')
    spec = TaskSpec(id='access-e4', phase='access', target=target, tool_profile='broker',
                    scope_ref=str(scope), evidence_dir=str(work / 'access'),
                    tools=[COMPILED_WORKFLOW_TOOL], commands=['Run the compiled workflow.'],
                    steps=[Step(id='compiled', command='workflow')])
    tasks = NativeTasks([spec], work, {name: {'target': target, 'test_data_only': True}
                                    for name in identities})
    class NoMCP:
        def __call__(self, *_):
            raise AssertionError('compiled workflows must execute through ChainExecutor')
        def terminate(self):
            pass
    broker = PythonBroker(budget=SharedBudget(tokens=150000, http=30, seconds=90), engine=engine,
                          executor=NoMCP(), workdir=work, private=private, tasks=tasks,
                          provider='https://unused.invalid/v1', models={'local'}, api_key='',
                          workflow_sender=sender)
    broker.tasks.active_spec = broker.tasks.specs[0]
    monkeypatch.setattr(broker, '_check_handoff', lambda _spec: None)
    return broker, broker.tasks.active_spec


def run_workflow_phase(broker, spec, binding_ref, monkeypatch):
    solver = PythonSolver(broker, model='local')
    requests = []
    def completion(body):
        requests.append(body)
        args = ({'binding_ref': binding_ref} if len(requests) == 1 else {
            'status': 'done', 'next': 'continue', 'steps': [{'id': 'compiled', 'status': 'done'}]})
        return {'choices': [{'message': {'tool_calls': [{'id': str(len(requests)), 'type': 'function',
            'function': {'name': COMPILED_WORKFLOW_TOOL if len(requests) == 1 else 'submit_phase_summary',
                         'arguments': json.dumps(args)}}]}}]}
    monkeypatch.setattr(broker, 'completion', completion)
    summary = solver.phase(spec)
    assert len(requests) == 2
    return solver, summary, requests
