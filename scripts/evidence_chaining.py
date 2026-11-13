"""P8 evidence-bound chaining on the existing SQLite graph/outbox.

Captures and operator facts are provenance, not vulnerability verdicts. Only the
recorded, deterministic control/effect oracle can produce validated_effect.
No network, credentials, new graph service or wire permission is provided here.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import sqlite3
import time
from urllib.parse import parse_qs, quote, unquote, urlsplit

try:
    from .authz_matrix import access_expectation, identity_fact, same_principal
except ImportError:
    from authz_matrix import access_expectation, identity_fact, same_principal

RELATIONS = frozenset({'produces_reference', 'consumes_reference', 'reads_resource',
                       'requires_identity', 'changes_state', 'validated_effect'})
CONTEXT = ('origin', 'tenant', 'run_id', 'session_id')
CHAIN_SCHEMA = 'evidence-chain/1.0'
MAX_TTL = 86400


class EvidenceError(ValueError):
    """An affected chain is not runnable; unrelated research can continue."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def origin(url):
    p = urlsplit(url)
    if p.scheme not in {'https', 'http'} or not p.hostname or p.username or p.password or p.fragment:
        raise EvidenceError('invalid_origin')
    port = p.port or (443 if p.scheme == 'https' else 80)
    return f'{p.scheme}://{p.hostname.lower()}:{port}'


def field(value, dotted):
    for key in dotted.split('.'):
        if isinstance(value, dict) and key in value:
            value = value[key]
        elif isinstance(value, list) and key.isdigit() and int(key) < len(value):
            value = value[int(key)]
        else:
            raise EvidenceError('missing_reference_field')
    return value


def response(record):
    r = record.get('response', {})
    if r.get('ok') is not True or type(r.get('status')) is not int or not 200 <= r['status'] < 300:
        raise EvidenceError('unsuccessful_observation')
    data = r.get('body')
    if not isinstance(data, dict):
        raise EvidenceError('unstructured_observation')
    return data


def request_value(record, selector):
    req = record['request']
    group, _, name = selector.partition('.')
    if group == 'body':
        return field(req.get('body'), name)
    if group == 'path' and name.isdigit():
        pieces = urlsplit(req['url']).path.split('/')
        if int(name) < len(pieces):
            return unquote(pieces[int(name)])
    if group == 'query':
        values = parse_qs(urlsplit(req['url']).query, keep_blank_values=True).get(name, [])
        if len(values) == 1:
            return values[0]
    raise EvidenceError('ambiguous_or_missing_request_slot')


def typed(value, kind):
    if kind == 'string' and type(value) is str and value:
        return value
    if kind == 'integer' and type(value) is int:
        return value
    raise EvidenceError('reference_type_mismatch')


class EvidenceGraph:
    """Hash-addressed evidence + typed edges + chain jobs in the memory DB.

    Graph projections are diagnostic. All execution/replay reads SQLite and
    rechecks hashes and TTL, even when a graph projection is stale or unavailable.
    """

    def __init__(self, db_path, clock=None):
        self.clock = clock or time.time
        self.db = sqlite3.connect(str(db_path))
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS p8_evidence (
                hash TEXT PRIMARY KEY, payload TEXT NOT NULL, invalidated INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS p8_relations (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, invalidated INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS p8_chain_jobs (
                id TEXT PRIMARY KEY, spec TEXT NOT NULL, plan TEXT, status TEXT NOT NULL, reason TEXT);
            CREATE TABLE IF NOT EXISTS p8_chain_dependencies (
                job_id TEXT NOT NULL, relation_id TEXT NOT NULL, PRIMARY KEY(job_id, relation_id));
            CREATE TABLE IF NOT EXISTS p8_chain_replays (
                job_id TEXT PRIMARY KEY, evidence_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS graph_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT, dedupe_key TEXT NOT NULL UNIQUE,
                operation TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT DEFAULT '',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP, completed_at DATETIME);
        ''')

    def close(self):
        self.db.close()

    def observe(self, record):
        """Store actual captures or explicit operator facts, never infer facts."""
        record = copy.deepcopy(record)
        context = record.get('context', {})
        if any(not isinstance(context.get(k), str) or not context[k] for k in CONTEXT):
            raise EvidenceError('missing_context')
        if origin(context['origin']) != context['origin']:
            raise EvidenceError('noncanonical_origin')
        start, end = record.get('observed_at'), record.get('expires_at')
        if (type(start) not in {float, int} or type(end) not in {float, int}
                or not math.isfinite(start) or not math.isfinite(end)
                or not 0 < end-start <= MAX_TTL or start > self.clock()):
            raise EvidenceError('invalid_evidence_ttl')
        if record.get('kind') == 'exchange':
            req = record.get('request', {})
            if origin(req.get('url', '')) != context['origin'] or req.get('method') not in {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH'}:
                raise EvidenceError('capture_origin_or_method_mismatch')
            if not record.get('identity_ref'):
                raise EvidenceError('missing_identity')
        elif record.get('kind') not in {'identity', 'resource', 'permission', 'replay'}:
            raise EvidenceError('unsupported_evidence_kind')
        h = digest(record)
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO p8_evidence(hash,payload) VALUES (?,?)', (h, canonical(record)))
        if record['kind'] != 'replay':
            self.refresh_blocked()
        return h

    def evidence(self, h, context=None):
        row = self.db.execute('SELECT * FROM p8_evidence WHERE hash=?', (h,)).fetchone()
        if not row:
            raise EvidenceError('missing_evidence')
        data = json.loads(row['payload'])
        if row['invalidated'] or digest(data) != h:
            raise EvidenceError('invalidated_evidence')
        if not data['observed_at'] <= self.clock() < data['expires_at']:
            raise EvidenceError('expired_evidence')
        if context is not None and any(data['context'].get(k) != context.get(k) for k in CONTEXT):
            raise EvidenceError('context_mismatch')
        return data

    def _relation(self, kind, source, target, hashes, details, context):
        records = [self.evidence(h, context) for h in hashes]
        relation = {'kind': kind, 'source': source, 'target': target,
                    'evidence_hashes': list(hashes), 'context': context, 'details': details,
                    'observed_at': max(r['observed_at'] for r in records),
                    'expires_at': min(r['expires_at'] for r in records)}
        rid = digest(relation)
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO p8_relations(id,payload) VALUES (?,?)', (rid, canonical(relation)))
            # Edge-specific nodes avoid overwriting parallel typed edges on graph
            # backends whose public add_edge is unique per source/target pair.
            payload = {'target': context['origin'], 'relation_id': rid, 'relation': relation}
            self.db.execute('INSERT OR IGNORE INTO graph_outbox(dedupe_key,operation,payload) VALUES (?,?,?)',
                            ('p8:' + rid, 'evidence_relation', canonical(payload)))
        return rid

    def relation(self, rid, context=None):
        row = self.db.execute('SELECT * FROM p8_relations WHERE id=?', (rid,)).fetchone()
        if not row:
            raise EvidenceError('missing_relation')
        r = json.loads(row['payload'])
        if row['invalidated'] or digest(r) != rid or r['kind'] not in RELATIONS:
            raise EvidenceError('invalidated_relation')
        if not r['observed_at'] <= self.clock() < r['expires_at']:
            raise EvidenceError('expired_relation')
        if context is not None and any(r['context'].get(k) != context.get(k) for k in CONTEXT):
            raise EvidenceError('context_mismatch')
        for h in r['evidence_hashes']:
            self.evidence(h, r['context'])
        return r

    def bind(self, producer, consumer, response_field, request_field, value_type, family):
        p, c = self.evidence(producer), self.evidence(consumer)
        ctx = p['context']
        self.evidence(consumer, ctx)
        if p['kind'] != 'exchange' or c['kind'] != 'exchange' or not family:
            raise EvidenceError('not_observed_data_flow')
        if p['observed_at'] > c['observed_at']:
            raise EvidenceError('reference_not_yet_observed')
        value = typed(field(response(p), response_field), value_type)
        consumed = typed(request_value(c, request_field), value_type)
        if value != consumed:
            raise EvidenceError('reference_mismatch')
        ref = 'reference:' + digest([ctx, family, value_type, value])
        details = {'family': family, 'value_type': value_type, 'value': value,
                   'response_field': response_field, 'request_field': request_field}
        a = self._relation('produces_reference', 'capture:' + producer, ref, [producer], details, ctx)
        b = self._relation('consumes_reference', ref, 'capture:' + consumer, [consumer], details, ctx)
        return {'produces_relation': a, 'consumes_relation': b, **details}

    def changes_state(self, before, after, path):
        a, b = self.evidence(before), self.evidence(after)
        ctx = a['context']
        self.evidence(after, ctx)
        if (a.get('identity_ref') != b.get('identity_ref') or a['request']['url'] != b['request']['url']
                or a['observed_at'] > b['observed_at']
                or type(field(response(a), 'id')) is not type(field(response(b), 'id'))
                or field(response(a), 'id') != field(response(b), 'id')):
            raise EvidenceError('state_resource_mismatch')
        x, y = field(response(a), path), field(response(b), path)
        if type(x) is not type(y) or x == y:
            raise EvidenceError('unobserved_state_change')
        return self._relation('changes_state', 'capture:' + before, 'capture:' + after,
                              [before, after], {'field': path, 'before': x, 'after': y}, ctx)

    def build_plan(self, spec):
        """Four observed reads: reference producer, owner, negative control, peer.

        Input is explicit source hashes and selectors. No semantic names, guessed
        URLs, writes, race probes or static terminal capabilities enter this plan.
        """
        ctx = spec['context']
        resource_record = self.evidence(spec['resource_hash'], ctx)
        permission = self.evidence(spec['permission_hash'], ctx)
        resource = resource_record.get('resource', {})
        if resource_record['kind'] != 'resource' or resource.get('test_data_only') is not True or resource.get('tenant') != ctx['tenant']:
            raise EvidenceError('test_object_mismatch')
        if permission['kind'] != 'permission' or permission.get('scope_allowed') is not True or permission.get('read_allowed') is not True:
            raise EvidenceError('scope_or_permission_denied')
        actor_records = {name: self.evidence(h, ctx) for name, h in spec['identity_hashes'].items()}
        actors = {}
        for name, record in actor_records.items():
            actor = record.get('actor', {})
            if (record['kind'] != 'identity' or record.get('identity_ref') != name
                    or actor.get('test_data_only') is not True
                    or identity_fact(actor, 'tenant') != ctx['tenant']
                    or not identity_fact(actor, 'principal') or not identity_fact(actor, 'authority')
                    or not record.get('credential_hash')):
                raise EvidenceError('identity_mismatch')
            actors[name] = actor
        owner, peer = spec['owner_identity'], spec['peer_identity']
        if (resource.get('owner_identity') != owner or same_principal(actors[owner], actors[peer]) is not False
                or access_expectation(resource, actors[peer], 'same_tenant_other_user') != 'deny'):
            raise EvidenceError('missing_sourced_access_denial')
        roles = ('producer', 'owner', 'negative', 'peer')
        records = {role: self.evidence(spec['captures'][role], ctx) for role in roles}
        if len(set(spec['captures'].values())) != 4:
            raise EvidenceError('independent_control_required')
        for role, record in records.items():
            expected = owner if role in {'producer', 'owner'} else peer
            if (record['kind'] != 'exchange' or record['identity_ref'] != expected
                    or record['request']['method'] != 'GET'
                    or record.get('credential_hash') != actor_records[expected]['credential_hash']):
                raise EvidenceError('capture_identity_or_permission_mismatch')
        if records['owner']['request']['url'] != records['peer']['request']['url']:
            raise EvidenceError('read_resource_mismatch')
        if resource.get('url') != records['owner']['request']['url']:
            raise EvidenceError('test_object_url_mismatch')
        slot = spec['request_field']
        ref_value = typed(field(response(records['producer']), spec['response_field']), spec['value_type'])
        if type(resource.get('resource_id')) is not type(ref_value) or resource['resource_id'] != ref_value:
            raise EvidenceError('test_object_reference_mismatch')
        if request_value(records['negative'], slot) == ref_value:
            raise EvidenceError('independent_control_required')
        # Control must use the same endpoint family, differing only at the
        # explicitly observed request slot (no unrelated 404 control).
        if bound_request(records['negative']['request'], slot, ref_value) != records['peer']['request']:
            raise EvidenceError('negative_control_route_mismatch')
        if permission.get('urls') != sorted({r['request']['url'] for r in records.values()}):
            raise EvidenceError('permission_resource_mismatch')
        relations, bindings = [], []
        for role in ('owner', 'peer'):
            binding = self.bind(spec['captures']['producer'], spec['captures'][role],
                                spec['response_field'], slot, spec['value_type'], resource['family'])
            bindings.append({'producer_step': 'producer', 'consumer_step': role, **binding})
            relations.extend([binding['produces_relation'], binding['consumes_relation']])
        steps = []
        for index, role in enumerate(roles):
            record = records[role]
            h, name = spec['captures'][role], record['identity_ref']
            relations.append(self._relation('requires_identity', 'capture:' + h, 'identity:' + name,
                [h, spec['identity_hashes'][name]], {'identity_ref': name}, ctx))
            if role in {'owner', 'peer'}:
                relations.append(self._relation('reads_resource', 'capture:' + h, 'resource:' + spec['resource_hash'],
                    [h, spec['resource_hash']], {'request_field': slot, 'value': ref_value}, ctx))
            steps.append({'id': role, 'tool': 'http_get', 'args': copy.deepcopy(record['request']),
                          'credential_hash': record['credential_hash'],
                          'identity_refs': [name], 'requires': [roles[index-1]] if index else [],
                          'expect': {'oracle': 'evidence_effect' if role == 'peer' else 'evidence_observation',
                                     'role': role},
                          'on_success': roles[index+1] if index < 3 else 'succeed', 'on_failure': 'abort'})
        plan = {'schema_version': 'action-manifest/1.0', 'kind': 'evidence_bound_read',
                'objective': 'Observed reference to test-object authorization effect',
                'target_ref': ctx['origin'], 'risk': 'active_read_only',
                'budget': {'max_requests': 4, 'max_duration_seconds': 30},
                'identity_refs': [owner, peer], 'steps': steps,
                'evidence_chain': {'schema_version': CHAIN_SCHEMA, 'spec': copy.deepcopy(spec),
                    'bindings': bindings, 'relation_ids': sorted(set(relations)),
                    'effect': {'oracle': 'p4_read_authorization', 'resource_field': spec['resource_field'],
                               'private_field': spec['private_field']}}}
        for rid in plan['evidence_chain']['relation_ids']:
            self.relation(rid, ctx)
        return plan

    def check_plan(self, manifest, runtime=None, identities=None):
        contract = manifest.get('evidence_chain', {})
        spec = contract['spec']
        # Recompilation checks immutable source data, typed slots, order,
        # prerequisites and terminal oracle; manifest flags confer no trust.
        expected = self.build_plan(spec)
        if {k: v for k, v in manifest.items() if k != 'manifest_hash'} != expected:
            raise EvidenceError('edited_evidence_chain')
        for rid in contract['relation_ids']:
            self.relation(rid, spec['context'])
        if runtime is not None:
            if any(runtime.get(k) != spec['context'].get(k) for k in CONTEXT):
                raise EvidenceError('runtime_context_mismatch')
            if runtime.get('scope_allowed') is not True or runtime.get('read_allowed') is not True:
                raise EvidenceError('runtime_scope_or_permission_denied')
            if runtime.get('resource_hash') != spec['resource_hash']:
                raise EvidenceError('runtime_test_object_mismatch')
            for name, h in spec['identity_hashes'].items():
                if digest((identities or {}).get(name, {})) != self.evidence(h)['credential_hash']:
                    raise EvidenceError('runtime_identity_mismatch')
        return expected

    def register_job(self, job_id, spec):
        try:
            plan = self.build_plan(spec)
            status, reason = 'ready', ''
        except (EvidenceError, KeyError, TypeError, ValueError) as exc:
            plan, status, reason = None, 'blocked', str(exc)
        with self.db:
            self.db.execute('INSERT INTO p8_chain_jobs VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET spec=excluded.spec,plan=excluded.plan,status=excluded.status,reason=excluded.reason',
                            (job_id, canonical(spec), canonical(plan), status, reason))
            # Replace only this job's dependencies when a refreshed spec arrives.
            self.db.execute('DELETE FROM p8_chain_dependencies WHERE job_id=?', (job_id,))
            self.db.execute('DELETE FROM p8_chain_replays WHERE job_id=?', (job_id,))
            for rid in (plan or {}).get('evidence_chain', {}).get('relation_ids', []):
                self.db.execute('INSERT INTO p8_chain_dependencies VALUES (?,?)', (job_id, rid))
        return self.job(job_id)

    def job(self, job_id):
        self.sweep()
        row = self.db.execute('SELECT * FROM p8_chain_jobs WHERE id=?', (job_id,)).fetchone()
        return dict(row) if row else None

    def refresh_blocked(self):
        rows = self.db.execute("SELECT id,spec FROM p8_chain_jobs WHERE status='blocked'").fetchall()
        return [self.register_job(r['id'], json.loads(r['spec'])) for r in rows]

    def invalidate(self, evidence_hash):
        with self.db:
            self.db.execute('UPDATE p8_evidence SET invalidated=1 WHERE hash=?', (evidence_hash,))
        return self.sweep()

    def sweep(self):
        invalid = []
        for row in self.db.execute('SELECT id FROM p8_relations WHERE invalidated=0').fetchall():
            try:
                self.relation(row['id'])
            except (EvidenceError, KeyError, TypeError, ValueError):
                invalid.append(row['id'])
        with self.db:
            for rid in invalid:
                self.db.execute('UPDATE p8_relations SET invalidated=1 WHERE id=?', (rid,))
                self.db.execute("UPDATE p8_chain_jobs SET status='invalidated',reason='expired_or_invalidated_edge' WHERE id IN (SELECT job_id FROM p8_chain_dependencies WHERE relation_id=?)", (rid,))
        # Identity, resource, permission and negative-control evidence are also
        # dependencies even where no typed edge consumes them directly.
        for row in self.db.execute("SELECT id,plan FROM p8_chain_jobs WHERE status NOT IN ('blocked','invalidated')").fetchall():
            try:
                self.check_plan(json.loads(row['plan']))
                replay = self.db.execute('SELECT evidence_hash FROM p8_chain_replays WHERE job_id=?', (row['id'],)).fetchone()
                if replay:
                    self.replay(replay['evidence_hash'])
            except (EvidenceError, KeyError, TypeError, ValueError):
                with self.db:
                    self.db.execute("UPDATE p8_chain_jobs SET status='invalidated',reason='expired_or_invalidated_prerequisite' WHERE id=?", (row['id'],))
        return invalid

    def seal_replay(self, manifest, exchanges):
        self.check_plan(manifest)
        ctx = manifest['evidence_chain']['spec']['context']
        verdict, detail = evaluate_trace(manifest, exchanges)
        hashes = [self.observe(exchanges[s['id']]) for s in manifest['steps']]
        proof_hashes = list(manifest['evidence_chain']['spec']['captures'].values())
        spec = manifest['evidence_chain']['spec']
        proof_hashes += [spec['resource_hash'], spec['permission_hash'], *spec['identity_hashes'].values()]
        expiry = min(self.evidence(h)['expires_at'] for h in hashes + proof_hashes)
        replay = {'kind': 'replay', 'context': ctx, 'observed_at': self.clock(), 'expires_at': expiry,
                  'manifest': manifest, 'exchange_hashes': dict(zip([s['id'] for s in manifest['steps']], hashes)),
                  'verdict': verdict, 'detail': detail}
        h = self.observe(replay)
        effect_relation = None
        if verdict == 'CONFIRMED':
            effect_relation = self._relation('validated_effect', 'chain:' + digest(manifest), 'effect:test_object_read_authorization',
                           [h, *hashes, *proof_hashes], {'oracle': 'p4_read_authorization', **detail}, ctx)
        with self.db:
            for row in self.db.execute('SELECT id,plan FROM p8_chain_jobs WHERE plan=?', (canonical(manifest),)).fetchall():
                self.db.execute("UPDATE p8_chain_jobs SET status='completed' WHERE id=?", (row['id'],))
                self.db.execute('INSERT OR REPLACE INTO p8_chain_replays VALUES (?,?)', (row['id'], h))
                if effect_relation:
                    self.db.execute('INSERT OR IGNORE INTO p8_chain_dependencies VALUES (?,?)', (row['id'], effect_relation))
        return {'replay_evidence_hash': h, 'verdict': verdict, 'effect': detail,
                'severity': 'medium' if verdict == 'CONFIRMED' else None,
                'reportable': False}

    def replay(self, evidence_hash):
        replay = self.evidence(evidence_hash)
        if replay['kind'] != 'replay':
            raise EvidenceError('not_replay_evidence')
        self.check_plan(replay['manifest'])
        exchanges = {name: self.evidence(h, replay['context']) for name, h in replay['exchange_hashes'].items()}
        verdict, detail = evaluate_trace(replay['manifest'], exchanges)
        if (verdict, detail) != (replay['verdict'], replay['detail']):
            raise EvidenceError('replay_verdict_mismatch')
        return {'verdict': verdict, 'effect': detail, 'replay_evidence_hash': evidence_hash, 'reportable': False}


def bound_request(request, selector, value):
    """Replace only the observed path/query slot, preserving all other bytes."""
    result = copy.deepcopy(request)
    group, _, name = selector.partition('.')
    if group == 'path' and name.isdigit():
        parts = urlsplit(result['url'])
        pieces = parts.path.split('/')
        if int(name) >= len(pieces):
            raise EvidenceError('missing_request_slot')
        pieces[int(name)] = quote(str(value), safe='')
        result['url'] = parts._replace(path='/'.join(pieces)).geturl()
    elif group == 'query':
        parts = urlsplit(result['url'])
        pairs = parts.query.split('&')
        matches = [i for i, p in enumerate(pairs) if unquote(p.partition('=')[0]) == name]
        if len(matches) != 1:
            raise EvidenceError('ambiguous_request_slot')
        i = matches[0]
        pairs[i] = pairs[i].partition('=')[0] + '=' + quote(str(value), safe='')
        result['url'] = parts._replace(query='&'.join(pairs)).geturl()
    else:
        raise EvidenceError('unsupported_read_binding_slot')
    return result


def evaluate_trace(manifest, exchanges):
    """P4 exact resource/private-field evidence plus independent negative control.

    P7's control/effect principle applies: HTTP 200 or merely connected edges
    cannot confirm access. Identity/privacy facts were checked before execution.
    """
    spec = manifest['evidence_chain']['spec']
    detail = {'oracle': 'p4_read_authorization', 'negative_control_passed': False,
              'violation_effect_observed': False, 'reason': 'missing_observations'}
    try:
        for step in manifest['steps']:
            record = exchanges[step['id']]
            if (record['context'] != spec['context'] or record['identity_ref'] != step['identity_refs'][0]
                    or record.get('credential_hash') != step['credential_hash']
                    or record['request'] != step['args']):
                raise EvidenceError('replay_context_or_request_mismatch')
        value = typed(field(response(exchanges['producer']), spec['response_field']), spec['value_type'])
        for binding in manifest['evidence_chain']['bindings']:
            if value != binding['value'] or typed(request_value(exchanges[binding['consumer_step']],
                    binding['request_field']), binding['value_type']) != value:
                raise EvidenceError('unvalidated_edge')
        owner = response(exchanges['owner'])
        neg = exchanges['negative']['response']
        control = neg.get('ok') is True and neg.get('status') in {403, 404} and not has_field(neg.get('body'), spec['private_field'])
        detail['negative_control_passed'] = control
        own_id, marker = field(owner, spec['resource_field']), field(owner, spec['private_field'])
        if type(own_id) is not type(value) or own_id != value or type(marker) is not str or not marker:
            raise EvidenceError('owner_resource_or_private_evidence_mismatch')
        peer = exchanges['peer']['response']
        if peer.get('ok') is True and peer.get('status') in {403, 404}:
            detail['reason'] = 'authorization_enforced' if control else 'negative_control_failed'
            return 'NOT_CONFIRMED', detail
        data = response(exchanges['peer'])
        peer_id, peer_marker = field(data, spec['resource_field']), field(data, spec['private_field'])
        effect = type(peer_id) is type(value) and peer_id == value and type(peer_marker) is str and peer_marker == marker
        detail.update(violation_effect_observed=effect,
                      reason='validated_effect' if effect and control else 'effect_or_control_mismatch')
        return ('CONFIRMED' if effect and control else 'NOT_CONFIRMED'), detail
    except (EvidenceError, KeyError, TypeError, ValueError) as exc:
        detail['reason'] = str(exc)
        return 'INCONCLUSIVE', detail


def manifest_errors(manifest):
    """Structural gate; evidence/TTL/trusted runtime checks belong to the store."""
    c = manifest.get('evidence_chain')
    if not isinstance(c, dict) or c.get('schema_version') != CHAIN_SCHEMA:
        return ['missing_evidence_chain_contract']
    roles = ['producer', 'owner', 'negative', 'peer']
    steps = manifest.get('steps', [])
    if (not isinstance(c.get('spec'), dict) or not c.get('bindings') or not c.get('relation_ids')
            or not isinstance(steps, list) or len(steps) != 4
            or any(not isinstance(s, dict) for s in steps)):
        return ['invalid_evidence_chain']
    for i, step in enumerate(steps):
        if (step.get('id') != roles[i] or step.get('tool') != 'http_get'
                or step.get('on_success') != (roles[i+1] if i < 3 else 'succeed')
                or step.get('on_failure') != 'abort'
                or step.get('requires', []) != ([roles[i-1]] if i else [])
                or step.get('expect', {}).get('oracle') != ('evidence_effect' if i == 3 else 'evidence_observation')):
            return ['edited_evidence_chain_route_or_oracle']
    return []


def has_field(value, path):
    try:
        field(value, path)
        return True
    except EvidenceError:
        return False
