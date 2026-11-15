"""Validator privacy and fresh-broker continuity, with signed loopback controls."""
import copy
import json
from pathlib import Path
import secrets
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from evidence_trust import attest, canonical_bytes
from full_agent_budget import SharedBudget
from full_agent_python_broker import PythonBroker, READ_TOOL
from full_agent_python_solver import PythonSolver
from full_agent_tasks import TaskRegistry
import python_identity_discovery as discovery
from workflow_checkpoint import PURPOSE as CHECKPOINT_PURPOSE, file_ref
from test_full_agent_python_solver import python_broker, terminal
from test_private_public_value_projection import assert_absent
from test_python_candidate_runtime import observe, replay_lab
from test_python_identity_discovery_integrity import provenance


@pytest.mark.parametrize('verdict', ['CONFIRMED', 'UNCONFIRMED'])
@pytest.mark.parametrize('serialized', [False, True])
def test_plain_validator_every_public_boundary(python_broker, verdict, serialized):
    sensitive = 'synthetic-' + secrets.token_hex(12) + '@owned.invalid'
    owned_id = secrets.token_hex(16)
    record = {'validation_id': secrets.token_hex(16), 'verdict': verdict, 'vuln_type': 'IDOR',
              'target': python_broker.tasks.specs[2].target + 'objects/' + owned_id + '?contact=' + sensitive,
              'differential': {'required_markers': [sensitive], 'shared_markers': [sensitive]},
              'execution_context': {'principal': sensitive, 'contact': sensitive, 'query': sensitive,
                                    'method': 'GET', 'carrier': 'query', 'param': 'contact'},
              'request_evidence': [{'excerpt': sensitive, 'request_url': 'http://127.0.0.1/' + owned_id}],
              'artifact': {'content_sha256': 'a' * 64}}
    original = copy.deepcopy(record)
    value = json.dumps(record) if serialized else record
    public = discovery.public_export(value)
    assert_absent(public, sensitive)
    assert_absent(public, owned_id)
    safe = json.loads(public) if serialized else public
    assert safe['validation_id'] == record['validation_id'] and safe['verdict'] == verdict
    assert safe['artifact']['content_sha256'] == 'a' * 64
    assert safe['execution_context']['param'] == 'contact'
    assert public == discovery.public_export(public) and record == original
    view = python_broker.view(value)
    page = python_broker.invoke(READ_TOOL, {'path': view['content_ref']['path']})
    spec = python_broker.tasks.specs[2]
    body = {'model': 'model', 'tools': [], 'messages': [
        {'role': 'system', 'content': 'host'}, {'role': 'user', 'content': json.dumps({
            'schema': 'python-workflow-v1', 'task_spec': spec.to_dict(), 'recent_results': [
                {'tool': 'validator_validate_idor', 'arguments': {'target_url': record['target'],
                     'param': 'contact', 'query': sensitive}, 'result': record}]})}]}
    wire, _, _ = python_broker.project_runtime_context(body, spec, None)
    for exported in (view, page, wire, python_broker.read_reference(view['content_ref'])):
        assert_absent(exported, sensitive)
        assert_absent(exported, owned_id)


@pytest.mark.parametrize('unsafe', [False, True])
@pytest.mark.parametrize('tool', ['validator_validate_sqli', 'hunter_run_web_loop'])
def test_signed_runtime_public_pages_preserve_exact_private_scoring(replay_lab, monkeypatch, unsafe, tool):
    from cco_validator_core import artifact_is_current, load_validation
    from cco_validator_core.evidence import validation_context
    from conftest import load_server
    from cco_validator_core.egress import scoped_wire_gate
    from wire_budget import campaign_wire_budget
    broker, target, wire_events = replay_lab
    sensitive = 'synthetic-' + secrets.token_hex(12) + '@owned.invalid'
    owned_id = secrets.token_hex(16)
    url = target + 'search/' + owned_id + ('-unsafe' if unsafe else '-safe') + '?term=alpha&contact=' + quote(sensitive, safe='')
    broker.tasks.bindings = ({'first': {'target': target, 'role': 'member', 'test_data_only': True,
                                      'owned_objects_private': True}} if tool == 'hunter_run_web_loop' else {})
    solver = PythonSolver(broker, model='model')
    source, spec = broker.tasks.specs[1:3]
    observe(broker, solver, source, [{'url': url}], identity='first' if broker.tasks.bindings else None)
    broker.tasks.active_spec = spec
    validator = load_server('validator')
    signed = []
    def execute(self, task):
        self.tasks.append(task)
        item = {'url': url, 'method': 'GET', 'carrier': 'query', 'param': 'term',
                'identity': 'first' if broker.tasks.bindings else 'anon', 'vuln_class': 'sqli', 'principal': sensitive}
        with campaign_wire_budget(task['reserved_request_cost'], secrets.token_hex(16)) as budget, scoped_wire_gate(
                lambda method, endpoint, headers: (method == 'GET' and endpoint.startswith(target), 'owned lab')):
            with validation_context(item):
                record = json.loads(validator.validate_sqli(url, 'term', boolean_only=True))
        signed.append(record)
        value = record if tool.startswith('validator_') else {
            'ok': True, 'run_id': 'run-' + secrets.token_hex(16), 'validation_queue': [item],
            'validations': [{**item, 'validation_id': record['validation_id'], 'verdict': record['verdict']}],
            'validator_record': record}
        return {'actual_request_cost': budget.used, 'result': {'output': value}}
    monkeypatch.setattr(type(broker.executor), '__call__', execute)
    args = {'target_url': url, 'param': 'term', 'boolean_only': True} if tool.startswith('validator_') else {
        'target': target, 'live': True, 'session_bindings': json.dumps(broker.tasks.bindings),
        'validation_profile': 'readonly_sqli_boolean'}
    view = broker.invoke(tool, args)
    record = signed[0]
    private_bytes = Path(record['artifact']['path']).read_bytes()
    expected = 'CONFIRMED' if unsafe else 'UNCONFIRMED'
    assert record['verdict'] == expected and artifact_is_current(record, expected_target=target)
    assert record['target'] == url and record['execution_context']['principal'] == sensitive
    attempts = broker.validation_attempts(spec)
    assert len(attempts) == 1 and attempts[0]['record'] == record
    summary = solver.compile_summary(spec, terminal(spec))
    assert summary['validation_funnel']['evidence_accepted'] == 1
    assert len(summary['validation_outcomes']) == 1
    assert len(summary['findings']) == int(unsafe)
    assert load_validation(record['validation_id']) == record
    assert Path(record['artifact']['path']).read_bytes() == private_bytes
    assert json.loads((broker.workdir / 'validator-artifacts' / (record['validation_id'] + '.json')).read_bytes()) == record
    before = len(wire_events)
    pages = []
    for ref in list(broker.references.values()):
        if ref['path'].startswith('context-archive/validator-') or ref == view['content_ref']:
            assert_absent(broker.read_reference(ref), sensitive)
            assert_absent(broker.read_reference(ref), owned_id)
            pages.append(broker.invoke(READ_TOOL, {'path': ref['path']})['result'])
    body = {'model': 'model', 'tools': [], 'messages': [
        {'role': 'system', 'content': 'host'}, {'role': 'user', 'content': json.dumps(solver.context(spec))}]}
    provider, _, _ = broker.project_runtime_context(body, spec, None)
    for public in [view, provider, *pages]:
        assert_absent(public, sensitive)
        assert_absent(public, owned_id)
    assert len(wire_events) == before and broker.budget.used['http'] == before


def save(case, *, interrupted=False):
    for ident, summary in case.solver.summaries.items():
        spec = next(s for s in case.broker.tasks.specs if s.id == ident)
        path = case.broker.tasks.summary_path(spec)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_bytes(summary))
    case.solver.coverage_gaps[case.spec.id] = [{'status': 'NOT TESTED', 'reason_code': 'request_budget_exhausted'}]
    ref = case.broker.archive({'note': 'bounded page'})
    case.broker.invoke(READ_TOOL, {'path': ref['path']})
    case.broker.invoke(READ_TOOL, {'path': ref['path']})
    if interrupted:
        case.solver.task_states[case.spec.id] = 'running'
        case.broker.budget.reserve('http', 7)
    case.solver._checkpoint_active = True
    case.solver.checkpoint.acquire()
    try:
        case.solver.save_checkpoint()
    finally:
        case.solver.checkpoint.release()
    return ref


def fresh(case):
    old = case.broker
    broker = PythonBroker(budget=SharedBudget(tokens=150000, http=300, seconds=900), engine=old.engine,
                          executor=old.executor, workdir=old.workdir, private=old.private,
                          provider=old.provider, models={'model'}, api_key='synthetic-offline-only')
    broker.tasks = TaskRegistry(copy.deepcopy(old.tasks.specs), old.workdir, copy.deepcopy(old.tasks.bindings))
    broker.catalog = copy.deepcopy(old.catalog)
    solver = PythonSolver(broker, model='model', resume=True)
    return broker, solver


def test_fresh_checkpoint_keeps_private_receipts_evidence_age_brake_and_gaps(provenance, monkeypatch):
    case = provenance
    public_ref = save(case)
    payload = case.solver.checkpoint.read()
    state = json.loads((case.broker.workdir.parent / payload['state_ref']['path']).read_bytes())
    assert state['private_discovery_sources'] == case.broker.private_discovery_sources
    evidence_paths = {str(case.broker.workdir.parent / r['path']) for r in payload['evidence']}
    for execution_path, ref in case.broker.private_discovery_sources.items():
        assert execution_path in evidence_paths and ref['path'] in evidence_paths
        seal = discovery._signed_reference(ref, discovery.SOURCE_PURPOSE)
        assert seal['producer_reference']['path'] in evidence_paths
    before = len(case.wire), copy.deepcopy(case.broker.budget.used), case.solver.expires_at
    broker, solver = fresh(case)
    try:
        solver.restore_checkpoint()
        assert broker.private_discovery_sources == case.broker.private_discovery_sources
        assert solver.coverage_gaps == case.solver.coverage_gaps
        assert solver.expires_at == before[2] and broker.budget.used == before[1]
        assert broker.read_progress == case.broker.read_progress
        spec = next(s for s in broker.tasks.specs if s.id == case.spec.id)
        broker.tasks.active_spec = spec
        assert broker.invoke(READ_TOOL, {'path': public_ref['path']})['result']['reason_code'] == 'archive_read_no_progress'
        hunter_ref = next(r['content_ref'] for r in broker.results if r['tool'] == 'hunter_run_web_loop')
        raw = broker.private_discovery_report(spec, hunter_ref)
        assert raw == case.broker.private_discovery_report(case.spec, hunter_ref)
        assert broker.validation_attempts(spec) == case.broker.validation_attempts(case.spec)
        context = solver.context(spec)
        for private_ref in broker.private_discovery_sources.values():
            assert private_ref['path'] not in json.dumps(context)
            assert private_ref['path'] not in broker.references
        path = discovery.prepare_discovery(broker, spec, case.arguments(case.overlap))
        restored = json.loads(path.read_bytes())['payload']
        assert restored['states'] == case.payload['states']
        assert discovery.load_discovery(case.target, case.actors(case.overlap), 24) == case.payload['states']
        for private_ref in broker.private_discovery_sources.values():
            with pytest.raises(ValueError):
                broker.invoke(READ_TOOL, {'path': private_ref['path']})
        assert len(case.wire) == before[0]
    finally:
        broker.close()


@pytest.mark.parametrize('confirmed', [False, True])
def test_hunter_authz_marker_record_pages_are_public_but_signed_file_is_exact(replay_lab, confirmed):
    from conftest import load_server
    from cco_validator_core.evidence import artifact_is_current
    broker, target, _wire = replay_lab
    hunter = load_server('hunter')
    sensitive = 'synthetic-' + secrets.token_hex(12) + '@owned.invalid'
    owned_id = secrets.token_hex(16)
    record = json.loads(hunter.analyze_authz_result(json.dumps({
        'target': target + 'objects/' + owned_id + '?contact=' + quote(sensitive, safe=''),
        'test_type': 'bola', 'required_markers': [sensitive],
        'authorized': {'status': 200, 'body': sensitive, 'markers': [sensitive]},
        'attacker': {'status': 200 if confirmed else 403,
                     'body': sensitive if confirmed else 'denied', 'markers': [sensitive] if confirmed else []}})))
    assert record['verdict'] == ('CONFIRMED' if confirmed else 'UNCONFIRMED')
    assert record['differential']['required_markers'] == [sensitive]
    assert record['differential']['shared_markers'] == ([sensitive] if confirmed else [])
    path = Path(record['artifact']['path'])
    original = path.read_bytes()
    assert artifact_is_current(record, expected_target=target)
    view = broker.view(record)
    page = broker.invoke(READ_TOOL, {'path': view['content_ref']['path']})
    for public in (view, page, broker.read_reference(view['content_ref'])):
        assert_absent(public, sensitive)
        assert_absent(public, owned_id)
    assert path.read_bytes() == original and json.loads(original) == record


@pytest.mark.parametrize('change', ['expired', 'expired_state', 'tampered_blob', 'missing_blob',
    'tampered_seal', 'missing_seal', 'tampered_execution', 'scope', 'policy'])
def test_fresh_checkpoint_rejects_stale_or_changed_private_chain(provenance, monkeypatch, change):
    case = provenance
    save(case)
    source = case.payload['sources'][0]
    seal = discovery._signed_reference(source['private_reference'], discovery.SOURCE_PURPOSE)
    if change.startswith(('tampered_', 'missing_')):
        ref = (seal['producer_reference'] if change.endswith('blob') else source[
            'private_reference' if change.endswith('seal') else 'execution_reference'])
        path = Path(ref['path'])
        if change.startswith('missing_'):
            path.unlink()
        else:
            path.write_bytes(path.read_bytes() + b' ')
    elif change == 'expired':
        observation = discovery._signed_reference(seal['producer_reference'], discovery.OBSERVATION_PURPOSE)
        monkeypatch.setattr(discovery, 'time', SimpleNamespace(time=lambda: observation['produced_at'] + discovery.TTL_SECONDS))
    elif change == 'expired_state':
        observed_at = case.payload['states'][case.names[0]]['observed_at']
        monkeypatch.setattr(discovery, 'time', SimpleNamespace(time=lambda: observed_at + discovery.TTL_SECONDS))
    else:
        import cco_validator_core.evidence as evidence
        monkeypatch.setattr(evidence, 'current_scope_revision' if change == 'scope' else 'current_policy_hash',
                            lambda: 'changed-control')
    before = len(case.wire), copy.deepcopy(case.broker.budget.used)
    broker, solver = fresh(case)
    try:
        with pytest.raises((ValueError, OSError)):
            solver.restore_checkpoint()
        assert not broker.private_discovery_sources
        assert len(case.wire) == before[0]
    finally:
        broker.close()


@pytest.mark.parametrize('change', ['producer_signature', 'seal_signature', 'task_contract',
                                  'arguments', 'invocation', 'missing_evidence', 'validation_signature'])
def test_fresh_checkpoint_revalidates_inner_authority_even_with_rehashed_outer_state(provenance, change):
    from cco_validator_core import load_validation
    case = provenance
    save(case)
    payload = case.solver.checkpoint.read()
    root = case.broker.workdir.parent
    state_path = root / payload['state_ref']['path']
    state = json.loads(state_path.read_bytes())
    execution_path, private_ref = next(iter(state['private_discovery_sources'].items()))
    seal_path = Path(private_ref['path'])
    seal = discovery._signed_reference(private_ref, discovery.SOURCE_PURPOSE)
    producer_path = Path(seal['producer_reference']['path'])
    if change == 'producer_signature':
        envelope = json.loads(producer_path.read_bytes())
        envelope['signature'] = 'invalid'
        producer_path.write_bytes(canonical_bytes(envelope))
        seal['producer_reference'] = discovery._reference(producer_path)
        seal_path.write_bytes(canonical_bytes(attest(seal, discovery.SOURCE_PURPOSE)))
    elif change == 'seal_signature':
        envelope = json.loads(seal_path.read_bytes())
        envelope['signature'] = 'invalid'
        seal_path.write_bytes(canonical_bytes(envelope))
    elif change in {'task_contract', 'arguments', 'invocation'}:
        key = {'task_contract': 'task_spec_sha256', 'arguments': 'arguments_sha256', 'invocation': 'invocation'}[change]
        seal[key] = 'unrelated-contract'
        seal_path.write_bytes(canonical_bytes(attest(seal, discovery.SOURCE_PURPOSE)))
    elif change == 'validation_signature':
        public = discovery._read_reference(seal['execution_reference'])['execution']['result']['output']
        record = load_validation(public['validations'][0]['validation_id'])
        record['artifact']['signature']['value'] = 'invalid'
        Path(record['artifact']['path']).write_bytes(canonical_bytes(record))
    state['private_discovery_sources'][execution_path] = discovery._reference(seal_path)
    state_path.write_bytes(canonical_bytes(state))
    payload['state_ref'] = file_ref(root, state_path)
    payload['evidence'] = [file_ref(root, ref['path']) for ref in payload['evidence']
                           if change != 'missing_evidence' or root / ref['path'] != producer_path]
    case.solver.checkpoint.path.write_bytes(canonical_bytes(attest(payload, CHECKPOINT_PURPOSE)))
    before = len(case.wire)
    broker, solver = fresh(case)
    try:
        with pytest.raises(ValueError):
            solver.restore_checkpoint()
        assert not broker.private_discovery_sources and len(case.wire) == before
    finally:
        broker.close()


def test_fresh_checkpoint_interrupted_dispatch_is_charged_once_and_never_replayed(provenance):
    case = provenance
    save(case, interrupted=True)
    before = len(case.wire), copy.deepcopy(case.broker.budget.used), len(case.broker.executor.tasks)
    broker, solver = fresh(case)
    try:
        solver.restore_checkpoint()
        assert solver.task_states[case.spec.id] == 'inconclusive'
        assert broker.budget.used['http'] == before[1]['http'] + 7 and not broker.budget.pending
        assert len(case.wire) == before[0] and len(broker.executor.tasks) == before[2]
        solver._checkpoint_active = True
        solver.checkpoint.acquire()
        solver.save_checkpoint()
        solver.checkpoint.release()
    finally:
        broker.close()
    broker, solver = fresh(case)
    try:
        solver.restore_checkpoint()
        assert solver.task_states[case.spec.id] == 'inconclusive'
        assert broker.budget.used['http'] == before[1]['http'] + 7
        assert len(case.wire) == before[0] and len(broker.executor.tasks) == before[2]
    finally:
        broker.close()
