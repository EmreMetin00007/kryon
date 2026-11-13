"""Socket-free P7 lab. All objects and principals are synthetic, local fixtures."""
from __future__ import annotations

import copy
import json
import uuid
from urllib.parse import urlparse

KINDS = ('write_authorization', 'schema_symmetry', 'idempotency_replay',
         'sequence_step_skip', 'state_transition')
IDENTITIES = {'owner': {'Authorization': 'Bearer p7-lab-owner'},
              'other': {'Authorization': 'Bearer p7-lab-other'}}


class LogicLab:
    def __init__(self, *, vulnerable=False, teardown='success'):
        self.vulnerable = vulnerable
        self.teardown = teardown
        self.objects = {}
        self.calls = []

    def setup(self, kind, role):
        if kind not in KINDS:
            raise ValueError('unknown lab scenario')
        rid = uuid.uuid4().hex
        self.objects[rid] = {'id': rid, 'title': 'initial', 'server_tag': 'initial',
                             'uses': 0, 'total': 100, 'prepared': False,
                             'status': 'draft', 'kind': kind,
                             'access_state': {'status': 'private', 'viewer_access': False}}
        if kind == 'state_transition' and role == 'probe':
            self.objects[rid]['access_state'] = {'status': 'shared', 'viewer_access': True}
        return 'http://p7.lab.test/objects/' + rid

    def close(self, url):
        if self.teardown == 'exception':
            raise RuntimeError('fixture close failed')
        if self.teardown == 'unknown':
            return None
        if self.teardown == 'failed':
            return False
        rid = urlparse(url).path.rsplit('/', 1)[-1]
        self.objects.pop(rid, None)
        return rid not in self.objects

    def sender(self, method, url, headers, body, timeout):
        self.calls.append((method, url))
        rid = urlparse(url).path.rsplit('/', 1)[-1]
        obj = self.objects.get(rid)
        if obj is None:
            return self.response(404, {'error': 'fixture absent'})
        if method == 'GET':
            return self.response(200, copy.deepcopy(obj))
        data = json.loads(body or '{}')
        if data.get('resource_id') != rid:
            return self.response(400, {'error': 'resource mismatch'})
        owner = headers.get('Authorization') == IDENTITIES['owner']['Authorization']
        op = data.get('op')
        if op == 'title':
            if not owner and not self.vulnerable:
                return self.response(403, {'error': 'owner required'})
            obj['title'] = data['title']
        elif op == 'server_tag':
            if self.vulnerable:
                obj['server_tag'] = data['server_tag']
        elif op == 'redeem':
            if obj['uses'] and not self.vulnerable:
                return self.response(409, {'error': 'single use'})
            obj['uses'] += 1
            obj['total'] -= 10
        elif op == 'prepare':
            obj['prepared'] = True
        elif op == 'complete':
            if not obj['prepared'] and not self.vulnerable:
                return self.response(409, {'error': 'prepare required'})
            obj['status'] = 'complete'
        elif op == 'share':
            obj['access_state'] = {'status': 'shared', 'viewer_access': True}
        elif op == 'private':
            obj['access_state'] = {'status': 'private', 'viewer_access': self.vulnerable}
        else:
            return self.response(400, {'error': 'unknown operation'})
        return self.response(200, {'id': rid, 'applied': True})

    @staticmethod
    def response(status, body):
        text = json.dumps(body)
        return {'ok': True, 'status': status, 'text': text, 'len': len(text),
                'headers': {}, 'location': '', 'error': None}

    def capture(self, kind, urls, *, session_id):
        """Capture actual handler responses on a fork, leaving fixtures pristine."""
        fork = copy.deepcopy(self)
        records, flows = [], {}
        workflow = uuid.uuid4().hex
        for role, url in urls.items():
            rid = urlparse(url).path.rsplit('/', 1)[-1]
            sequence = [('GET', {}, 'owner')]
            if role == 'control':
                actions = [('title', {'title': 'normal'}, 'owner')]
                if kind == 'idempotency_replay':
                    actions = [('redeem', {'coupon': 'P7-ONE'}, 'owner')]
                elif kind == 'sequence_step_skip':
                    actions = [('prepare', {}, 'owner'), ('complete', {}, 'owner')]
                elif kind == 'state_transition':
                    actions = [('share', {}, 'owner')]
            else:
                actions = {
                    'write_authorization': [('title', {'title': 'tampered'}, 'other')],
                    'schema_symmetry': [('server_tag', {'server_tag': 'tampered'}, 'owner')],
                    'idempotency_replay': [('redeem', {'coupon': 'P7-ONE'}, 'owner')] * 2,
                    'sequence_step_skip': [('complete', {}, 'owner')],
                    'state_transition': [('private', {}, 'owner')],
                }[kind]
            sequence.extend(('POST', {'resource_id': rid, 'op': op, **values}, actor)
                            for op, values, actor in actions)
            sequence.append(('GET', {}, 'owner'))
            ids = []
            before_id = ''
            for idx, (method, payload, actor) in enumerate(sequence):
                cid = f'{role}-{idx}'
                ctx = {'source': 'capture', 'capture_id': cid, 'workflow_id': workflow,
                       'session_id': session_id, 'resource_id': rid, 'identity_ref': actor}
                if method == 'POST':
                    ctx['response_links'] = [{'producer': before_id, 'response_field': 'id',
                                              'request_field': 'body.resource_id'}]
                resp = fork.sender(method, url, IDENTITIES[actor], json.dumps(payload), 1)
                record = {'method': method, 'url': url, 'status': resp['status'],
                          'req_body': json.dumps(payload), 'resp_body': resp['text'],
                          'observed_context': ctx}
                records.append(record)
                ids.append(cid)
                if idx == 0:
                    before_id = cid
            flows[role] = {'before': ids[0], 'actions': ids[1:-1], 'after': ids[-1]}
        controls = {
            'write_authorization': ('title', 'initial', 'normal'),
            'schema_symmetry': ('title', 'initial', 'normal'),
            'idempotency_replay': ('uses', 0, 1),
            'sequence_step_skip': ('status', 'draft', 'complete'),
            'state_transition': ('access_state', {'status': 'private', 'viewer_access': False},
                                 {'status': 'shared', 'viewer_access': True}),
        }
        probes = {
            'write_authorization': ('title', 'initial', 'tampered'),
            'schema_symmetry': ('server_tag', 'initial', 'tampered'),
            'idempotency_replay': ('uses', 0, 2),
            'sequence_step_skip': ('status', 'draft', 'complete'),
            'state_transition': ('access_state', {'status': 'shared', 'viewer_access': True},
                                 {'status': 'private', 'viewer_access': True}),
        }
        rules = {
            'write_authorization': ('Only the owner may change the title.', 'An owner edit is legitimate.'),
            'schema_symmetry': ('The server-owned tag cannot be bound from input.', 'A normal editable title may change.'),
            'idempotency_replay': ('One coupon can produce at most one redemption.', 'One discount is legitimate; cart totals can decrease.'),
            'sequence_step_skip': ('Completion requires preparation on this object.', 'A previously prepared object may complete.'),
            'state_transition': ('Making a share private revokes viewer access.', 'A shared resource permits viewer access.'),
        }
        effect = lambda triple: dict(zip(('field', 'before', 'after'), triple))
        contract = {'kind': kind, 'expected_rule': rules[kind][0],
                    'alternative_explanation': rules[kind][1],
                    'evidence_ref': 'p7-local-handler-rule:' + kind,
                    'control': effect(controls[kind]), 'probe': effect(probes[kind])}
        probe = next(r for r in records if r['observed_context']['capture_id'] == flows['probe']['actions'][0])
        probe['observed_context']['business_rules'] = [{'contract': contract, **flows}]
        return records
