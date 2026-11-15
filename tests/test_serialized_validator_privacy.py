"""Adversarial public serialization controls; canonical signed inputs stay private."""
import copy
import hashlib
import json
from pathlib import Path
import secrets
import threading
from urllib.parse import quote

import pytest

from full_agent_python_broker import READ_TOOL
import python_identity_discovery as discovery
from test_full_agent_python_solver import python_broker
from test_private_public_value_projection import assert_absent


FORMATS = ('dict', 'plain-json', 'whitespace-json', 'list', 'whitespace-list-json',
           'nested', 'nested-whitespace-json', 'json-string', 'whitespace-json-string',
           'nested-json-string', 'list-json-string')


def representation(record, shape, kind):
    value = copy.deepcopy(record)
    if kind == 'hunter':
        value = {'ok': True, 'validations': [copy.deepcopy(record)], 'validator_record': value}
    serialized = ' \r\n\t' + json.dumps(value) + '\t\r\n '
    return {
        'dict': value, 'plain-json': json.dumps(value), 'whitespace-json': serialized,
        'list': [value], 'whitespace-list-json': ' \n\t' + json.dumps([serialized, value]),
        'nested': {'output': {'items': [value]}},
        'nested-whitespace-json': {'output': {'items': [serialized]}},
        'json-string': json.dumps(serialized),
        'whitespace-json-string': '\t\r\n ' + json.dumps(serialized),
        'nested-json-string': {'output': json.dumps({'items': [json.dumps(serialized)]})},
        'list-json-string': '\n' + json.dumps([json.dumps(serialized), {'output': serialized}]),
    }[shape]


def unpack(value):
    """Independent test decoding, not production recognition logic."""
    if isinstance(value, str):
        try:
            return unpack(json.loads(value))
        except ValueError:
            return value
    if isinstance(value, list):
        return [unpack(item) for item in value]
    if isinstance(value, dict):
        return {key: unpack(item) for key, item in value.items()}
    return value


def records(value):
    value = unpack(value)
    if isinstance(value, dict):
        if {'validation_id', 'verdict', 'artifact'} <= value.keys():
            yield value
        for item in value.values():
            yield from records(item)
    elif isinstance(value, list):
        for item in value:
            yield from records(item)


def public_boundaries(broker, value, record, kind, private_values, *, all_pages=True):
    spec = broker.tasks.specs[2]
    broker.tasks.active_spec = spec
    before = broker.calls, broker.budget.used['http'], len(broker.executor.tasks)
    public = discovery.public_export(value)
    view = broker.view(value)
    ref = view['content_ref']
    archive = broker.read_reference(ref)
    raw = broker._read_reference_bytes(ref)
    assert json.loads(raw) == archive and hashlib.sha256(raw).hexdigest() == ref['sha256']
    # Every archive byte is checked below. Full pagination uses bounded records;
    # large signed duplicates sample first/middle/final pages under existing caps.
    text = raw.decode()
    offsets = list(range(0, len(text), 3000))
    if not all_pages:
        offsets = sorted({offsets[0], offsets[len(offsets) // 2], offsets[-1]})
    pages = []
    for offset in offsets:
        page = broker.invoke(READ_TOOL, {'path': ref['path'], 'offset': offset})['result']
        pages.append(page)
        assert page['text'] == text[offset:offset + 3000]
        assert page['eof'] == (offset + 3000 >= len(text))
        assert page['next_offset'] == (None if page['eof'] else offset + 3000)
    if all_pages:
        assert ''.join(page['text'] for page in pages) == text
    context = {'schema': 'python-workflow-v1', 'task_spec': spec.to_dict(), 'recent_results': [
        {'tool': 'hunter_run_web_loop' if kind == 'hunter' else 'validator_validate_idor',
         'arguments': {'target_url': record['target']}, 'result': value}]}
    body = {'model': 'model', 'tools': [], 'messages': [
        {'role': 'system', 'content': 'host'}, {'role': 'user', 'content': json.dumps(context)}]}
    provider, _, _ = broker.project_runtime_context(body, spec, None)
    for exported in (public, view, archive, *pages, provider):
        for private in private_values:
            assert_absent(exported, private)
    assert public == discovery.public_export(public)
    for safe in records(public):
        assert safe['verdict'] == record['verdict']
        assert safe['validation_id'] == record['validation_id']
        assert safe['artifact']['content_sha256'] == record['artifact']['content_sha256']
    assert list(records(public)), 'Projection must retain usable verdict/ID/digest semantics'
    assert before == (broker.calls, broker.budget.used['http'], len(broker.executor.tasks))


@pytest.mark.parametrize('verdict', ['CONFIRMED', 'UNCONFIRMED'])
@pytest.mark.parametrize('kind', ['direct', 'hunter'])
@pytest.mark.parametrize('shape', FORMATS)
def test_serialized_validator_all_public_boundaries(python_broker, verdict, kind, shape):
    marker = 'synthetic-' + secrets.token_hex(12) + '@owned.invalid'
    principal, contact, owned = (secrets.token_hex(16) for _ in range(3))
    url = python_broker.tasks.specs[2].target + 'objects/' + owned + '?contact=' + quote(contact)
    record = {'validation_id': secrets.token_hex(16), 'verdict': verdict, 'vuln_type': 'IDOR',
              'target': url, 'differential': {'required_markers': [marker], 'shared_markers': [marker]},
              'execution_context': {'principal': principal, 'contact': contact, 'method': 'GET',
                                    'carrier': 'query', 'param': 'contact'},
              'request_evidence': [{'request_url': url, 'excerpt': marker}],
              'artifact': {'content_sha256': secrets.token_hex(32)}}
    original = copy.deepcopy(record)
    value = representation(record, shape, kind)
    value_before = copy.deepcopy(value)
    public_boundaries(python_broker, value, record, kind, [marker, principal, contact, owned, url])
    assert record == original and value == value_before


@pytest.mark.parametrize('whitespace', [' ', '\t', '\r', '\n', ' \t\r\n'])
def test_each_json_whitespace_character_is_recognized(whitespace):
    marker = 'synthetic-' + secrets.token_hex(16)
    record = {'validation_id': secrets.token_hex(16), 'verdict': 'UNCONFIRMED',
              'differential': {'shared_markers': [marker]}, 'execution_context': {'principal': marker}}
    safe = discovery.public_export(whitespace + json.dumps(record) + whitespace)
    assert_absent(safe, marker)
    assert unpack(safe)['verdict'] == 'UNCONFIRMED'


def test_long_serialized_view_archive_and_all_pages_are_public(python_broker):
    marker, owned = 'synthetic-' + secrets.token_hex(16), secrets.token_hex(16)
    record = {'validation_id': secrets.token_hex(16), 'verdict': 'CONFIRMED', 'vuln_type': 'IDOR',
              'target': python_broker.tasks.specs[2].target + owned,
              'differential': {'required_markers': [marker]},
              'artifact': {'content_sha256': secrets.token_hex(32)},
              'request_evidence': [{'excerpt': marker, 'response_sha256': secrets.token_hex(32)} for _ in range(90)]}
    value = representation(record, 'whitespace-json', 'direct')
    view = python_broker.view(value)
    assert view['omitted'] and view['content_ref']['bytes'] > 3000
    public_boundaries(python_broker, value, record, 'direct', [marker, owned])


@pytest.mark.parametrize('shape', ['oversized', 'deep-json', 'deep-strings', 'deep-containers'])
def test_serialization_limits_fail_closed_without_unbounded_decoding(shape, monkeypatch):
    from conftest import load_server
    load_server('hunter')
    from cco_hunter_core import request_context
    marker = 'synthetic-' + secrets.token_hex(16)
    value = ' \n' + json.dumps({'validation_id': secrets.token_hex(16), 'verdict': 'CONFIRMED',
                                 'execution_context': {'principal': marker}})
    if shape == 'oversized':
        value += ' ' * (16 * 1024 * 1024)
        def no_parse(_value):
            raise AssertionError('oversized serialization must not reach the JSON parser')
        monkeypatch.setattr(request_context.json, 'loads', no_parse)
    elif shape == 'deep-json':
        value = '\t' + '[' * 2000 + value + ']' * 2000
    elif shape == 'deep-strings':
        # Linear size growth; nested serialized objects, not exponential escaping.
        for _ in range(80):
            value = {'output': value}
            value = '\n' + json.dumps(value) if _ % 8 == 0 else value
    else:
        for _ in range(100):
            value = [value]
    safe = discovery.public_export(value)
    assert_absent(safe, marker)
    assert safe == discovery.public_export(safe)


@pytest.mark.parametrize('value', ['ordinary prose', ' \nnot JSON', ' \t{"note": "ordinary"}',
                                  ' \n[1, true, null]', ' \n"ordinary prose"'])
def test_unrelated_nonvalidator_text_and_json_remain_exact(value):
    assert discovery.public_export(value) == value


def test_serialization_byte_limit_counts_utf8_before_parsing(monkeypatch):
    from conftest import load_server
    load_server('hunter')
    from cco_hunter_core import request_context
    marker = 'synthetic-' + secrets.token_hex(16)
    value = '\n' + json.dumps({'validation_id': secrets.token_hex(16), 'verdict': 'UNCONFIRMED',
        'execution_context': {'principal': marker}, 'excerpt': '\U0001f512' * (4 * 1024 * 1024)}, ensure_ascii=False)
    assert len(value) < 16 * 1024 * 1024 < len(value.encode())
    def no_parse(_value):
        raise AssertionError('UTF-8 byte limit must be enforced before parsing')
    monkeypatch.setattr(request_context.json, 'loads', no_parse)
    safe = discovery.public_export(value)
    assert_absent(safe, marker)
    assert safe.startswith('opaque:') and safe == discovery.public_export(safe)


@pytest.mark.parametrize('kind', ['direct', 'hunter'])
@pytest.mark.parametrize('shape', FORMATS)
@pytest.mark.parametrize('public_verdict', ['CONFIRMED', 'UNCONFIRMED'])
def test_real_signed_producers_exact_private_bytes_and_scorer_denominators(python_broker, monkeypatch, kind, shape, public_verdict):
    from conftest import load_server
    validator = load_server('validator')
    from cco_validator_core.evidence import artifact_is_current, load_validation, validation_context
    from cco_validator_core.egress import scoped_wire_gate
    from full_agent_holdout import evaluate
    from full_agent_launcher import lab_policy
    from lab import readonly_sqli_holdout as lab_module
    from wire_budget import campaign_wire_budget

    lab = lab_module.serve(secrets.randbits(63))
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    target = 'http://127.0.0.1:' + str(lab.server_port) + '/'
    broker = python_broker
    for spec in broker.tasks.specs:
        spec.target = target
    spec = broker.tasks.specs[2]
    broker.tasks.active_spec = spec
    monkeypatch.setattr(broker, '_check_handoff', lambda spec: None)
    monkeypatch.setattr(broker.engine, 'tool_capability', lambda tool: {'network': True})
    scope, policy = lab_policy(target)
    for name, value in (('scope', scope), ('policy', policy)):
        p = broker.private / (name + '.json')
        p.write_text(json.dumps(value))
        monkeypatch.setenv('CCO_SCOPE_FILE' if name == 'scope' else 'CCO_PROGRAM_POLICY_FILE', str(p))
    marker, run_id = 'owned-' + secrets.token_hex(12) + '@synthetic.invalid', 'run-' + secrets.token_hex(16)
    cases = [next(c for c in lab.blind_state['truth'] if c['expected'] == 'positive' and c['context'] == 'numeric'),
             next(c for c in lab.blind_state['truth'] if c['negative_behavior'] == 'parameterized' and c['context'] == 'numeric')]
    current, signed = {}, []
    def execute(self, task):
        self.tasks.append(task)
        with campaign_wire_budget(task['reserved_request_cost'], secrets.token_hex(16)) as budget:
            with scoped_wire_gate(lambda method, endpoint, headers: (method == 'GET' and endpoint.startswith(target), 'owned offline control')):
                with validation_context(current):
                    record = json.loads(validator.validate_sqli(current['url'], current['param'], boolean_only=True))
        signed.append(record)
        value = record if kind == 'direct' else {
            'ok': True, 'run_id': run_id, 'validation_queue': [copy.deepcopy(current)],
            'validations': [{**current, 'validation_id': record['validation_id'], 'verdict': record['verdict']}],
            'validator_record': record}
        return {'actual_request_cost': budget.used, 'result': {'output': value}}
    monkeypatch.setattr(type(broker.executor), '__call__', execute)
    try:
        artifacts, originals, scoring_originals = [], [], []
        for case in cases:
            current.clear()
            current.update(url=target.rstrip('/') + case['path'] + '?id=1', param=case['param'], method='GET',
                           carrier='query', identity='anon', vuln_class='sql_injection', run_id=run_id, principal=marker)
            tool = 'validator_validate_sqli' if kind == 'direct' else 'hunter_run_web_loop'
            args = {'target_url': current['url'], 'param': 'id', 'boolean_only': True} if kind == 'direct' else {
                'target': target, 'live': True, 'session_bindings': '{}', 'validation_profile': 'readonly_sqli_boolean'}
            broker.invoke(tool, args)
            record = signed[-1]
            raw = Path(record['artifact']['path']).read_bytes()
            originals.append(raw)
            scoring_path = broker.workdir / 'validator-artifacts' / (record['validation_id'] + '.json')
            scoring_originals.append(scoring_path.read_bytes())
            assert json.loads(scoring_originals[-1]) == record
            artifacts.append({'record': record, 'path': record['artifact']['path'], 'sha256': hashlib.sha256(raw).hexdigest()})
            assert record['verdict'] == ('CONFIRMED' if case['expected'] == 'positive' else 'UNCONFIRMED')
            assert record['execution_context']['principal'] == marker and record['target'] == current['url']
        def score():
            return evaluate(lab.blind_state['truth'], lab.blind_state['wire'], artifacts, target=target, run_id=run_id,
                            verify_artifact=lambda r: artifact_is_current(r, expected_target=target))
        before = score()
        assert before['recall'] == {'numerator': 1, 'denominator': 8, 'value': 0.125}
        assert before['negative_coverage'] == {'numerator': 1, 'denominator': 8, 'value': 0.125}
        assert before['false_positives'] == {'numerator': 0, 'denominator': 1, 'value': 0.0}
        assert before['rejected_evidence'] == []
        attempts = broker.validation_attempts(spec)
        assert len(attempts) == 2 and {r['record']['validation_id'] for r in attempts} == {r['validation_id'] for r in signed}
        for record, raw, scoring_raw in zip(signed, originals, scoring_originals):
            owned = record['target'].split('/lookup/')[1].split('?')[0]
            # Separate verdict cases keep full pagination inside unchanged phase caps.
            if record['verdict'] == public_verdict:
                public_boundaries(broker, representation(record, shape, kind), record, kind,
                                  [marker, owned, record['target']], all_pages=False)
            assert Path(record['artifact']['path']).read_bytes() == raw
            assert load_validation(record['validation_id']) == record
            scoring_path = broker.workdir / 'validator-artifacts' / (record['validation_id'] + '.json')
            assert scoring_path.read_bytes() == scoring_raw and json.loads(scoring_raw) == record
        assert broker.validation_attempts(spec) == attempts and score() == before and broker.calls == 0
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join()
        lab.blind_state['db'].close()


@pytest.mark.parametrize('confirmed', [False, True])
@pytest.mark.parametrize('shape', FORMATS)
def test_real_hunter_authz_signed_whitespace_and_string_variants(python_broker, confirmed, shape):
    from conftest import load_server
    hunter = load_server('hunter')
    from cco_validator_core.evidence import artifact_is_current
    marker, owned = 'owned-' + secrets.token_hex(12) + '@synthetic.invalid', secrets.token_hex(16)
    target = python_broker.tasks.specs[2].target
    record = json.loads(hunter.analyze_authz_result(json.dumps({
        'target': target + 'objects/' + owned + '?contact=' + quote(marker), 'test_type': 'bola',
        'required_markers': [marker], 'authorized': {'status': 200, 'body': marker, 'markers': [marker]},
        'attacker': {'status': 200 if confirmed else 403, 'body': marker if confirmed else 'denied',
                     'markers': [marker] if confirmed else []}})))
    assert record['verdict'] == ('CONFIRMED' if confirmed else 'UNCONFIRMED')
    assert record['differential']['required_markers'] == [marker]
    path = Path(record['artifact']['path'])
    raw = path.read_bytes()
    assert artifact_is_current(record, expected_target=target)
    public_boundaries(python_broker, representation(record, shape, 'hunter'), record, 'hunter', [marker, owned, record['target']])
    assert path.read_bytes() == raw and json.loads(raw) == record
