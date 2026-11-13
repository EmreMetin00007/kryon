"""Durable observation-level hypotheses. Metadata never grants execution.

CampaignRuntime retains all claims, leases and wire budgets. Terminal states
require a validator receipt accepted by the existing evidence verifier.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .normalize import canonical_target

STATES = ('proposed', 'ready', 'running', 'blocked', 'inconclusive', 'tested_no_violation', 'confirmed')
TERMINAL = {'tested_no_violation', 'confirmed'}
EXTRA_DIMENSIONS = ('resource_key', 'resource_family', 'state_key', 'variant_key')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def label(value, default='unspecified'):
    value = str(value or '')
    if not value:
        return default
    return value if re.fullmatch(r'[A-Za-z0-9_.:/{}\[\]-]{1,256}', value) else 'opaque:' + digest(value)


def extensions(row):
    """Hash concrete resource/state/variant values; never store their contents."""
    out = {}
    for source, key in (('resource_id', 'resource_key'), ('request_state', 'state_key'), ('variant_id', 'variant_key')):
        if row.get(key):
            value = str(row[key])
            if not re.fullmatch(r'[a-f0-9]{64}', value):
                raise ValueError('invalid hypothesis dimension digest')
            out[key] = value
        elif row.get(source) is not None:
            out[key] = digest(row[source])
    if row.get('resource_family'):
        out['resource_family'] = label(row['resource_family'], '')
    return out


def dimension(target, row, context):
    url = str(row.get('url') or row.get('endpoint') or '')
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username is not None:
        raise ValueError('invalid hypothesis URL')
    safe_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                          urlencode([(k, '<redacted>') for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]), ''))
    data = {'context': str(context), 'target_key': digest(canonical_target(target)), 'url': safe_url,
            'request_key': digest(url), 'operation_id': label(row.get('operation_id'), digest([row.get('method', 'GET'), safe_url])),
            'method': str(row.get('method') or 'GET').upper(),
            'carrier': label(row.get('carrier') or row.get('location'), 'query'),
            'param': label(row.get('param'), ''),
            'identity': label(row.get('attacker_identity') or row.get('identity')),
            'resource_owner': label(row.get('owner_identity') or row.get('resource_owner')),
            'run_id': label(row.get('run_id')), 'observation_id': label(row.get('observation_id'), ''),
            'hypothesis_type': label('path_traversal' if row.get('vuln_class') == 'lfi' else row.get('vuln_class'), ''),
            **extensions(row)}
    if row.get('access_rule_hash'):
        data['access_rule_hash'] = label(row['access_rule_hash'], '')
    if not data['hypothesis_type']:
        raise ValueError('hypothesis type required')
    return digest(data), data


def ensure_schema(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS web_hypotheses (
        fingerprint TEXT PRIMARY KEY, target_key TEXT NOT NULL, context_key TEXT NOT NULL,
        dimension_json TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
        metadata_json TEXT NOT NULL, blockers_json TEXT NOT NULL DEFAULT '[]',
        validation_id TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 1)''')
    conn.execute('CREATE INDEX IF NOT EXISTS web_hypotheses_context ON web_hypotheses(target_key,context_key,status)')


def metric(value, default=0):
    try:
        number = float(value)
        return max(0, min(1e6, number)) if math.isfinite(number) else default
    except (ValueError, TypeError):
        return default


def priority(row):
    """Explainable ordering, not a calibrated probability or an execution grant."""
    return (row.get('status') != 'ready', -metric(row.get('observation_quality')),
            -metric(row.get('coverage_contribution'), 1), -metric(row.get('impact')),
            metric(row.get('estimated_requests'), 1), metric(row.get('estimated_seconds'), 1))


def observe(conn, target, row, context='inventory'):
    ensure_schema(conn)
    key, data = dimension(target, row, context)
    metadata = {k: metric(row.get(k), default) for k, default in (
        ('observation_quality', 1), ('coverage_contribution', 1), ('impact', 0),
        ('estimated_requests', 1), ('estimated_seconds', 1))}
    # Initial status is always proposed: a source observation is not admission.
    metadata['vector_group'] = label(row.get('vector_group') or row.get('vuln_class'), '')
    conn.execute('INSERT OR IGNORE INTO web_hypotheses '
                 '(fingerprint,target_key,context_key,dimension_json,status,reason,metadata_json) VALUES (?,?,?,?,?,?,?)',
                 (key, digest(canonical_target(target)), context, json.dumps(data, sort_keys=True), 'proposed',
                  'observation_received', json.dumps(metadata, sort_keys=True)))
    return key


def transition(conn, key, state, *, reason='', blockers=()):
    if state not in STATES or state in TERMINAL:
        raise ValueError('terminal hypotheses require verified validator evidence')
    if state == 'blocked' and not reason:
        raise ValueError('blocked hypotheses require a reason')
    clean = [{'kind': label(b['kind']), 'subject': label(b['subject']), 'version': digest(b['version'])}
             for b in blockers]
    # Task completion cannot overwrite a verified hypothesis or trigger a retry.
    changed = conn.execute('UPDATE web_hypotheses SET status=?,reason=?,blockers_json=?,revision=revision+1 '
                          "WHERE fingerprint=? AND status NOT IN ('confirmed','tested_no_violation') "
                          'AND (status<>? OR reason<>? OR blockers_json<>?)',
                          (state, label(reason, ''), json.dumps(clean, sort_keys=True), key,
                           state, label(reason, ''), json.dumps(clean, sort_keys=True)))
    return bool(changed.rowcount)


def complete(conn, key, receipt, verify):
    """The caller supplies its current signed-artifact verifier, not a report flag."""
    old = conn.execute('SELECT dimension_json FROM web_hypotheses WHERE fingerprint=?', (key,)).fetchone()
    if (not old or not callable(verify) or not receipt.get('validation_id')
            or receipt.get('status') not in {'confirmed', 'tested_clean'}
            or not verify(json.loads(old[0]), receipt)):
        return False
    state = 'confirmed' if receipt['status'] == 'confirmed' else 'tested_no_violation'
    conn.execute('UPDATE web_hypotheses SET status=?,validation_id=?,reason=?,blockers_json=\'[]\',revision=revision+1 '
                 'WHERE fingerprint=? AND (status<>? OR validation_id<>?)',
                 (state, label(receipt['validation_id'], ''), 'verified_validator_evidence', key,
                  state, label(receipt['validation_id'], '')))
    return True


def resolve(conn, target, context, *, kind, subject, previous_version, new_version):
    """A changed dependency reopens only matching blocked work for readmission."""
    if digest(previous_version) == digest(new_version):
        return []
    reopened = []
    for row in list_hypotheses(conn, target, context):
        if row['status'] != 'blocked':
            continue
        blockers = row['blockers']
        matched = {'kind': kind, 'subject': subject, 'version': digest(previous_version)}
        if matched not in blockers:
            continue
        remaining = [b for b in blockers if b != matched]
        state = 'blocked' if remaining else 'proposed'
        conn.execute('UPDATE web_hypotheses SET status=?,reason=?,blockers_json=?,revision=revision+1 WHERE fingerprint=?',
                     (state, 'dependency_changed', json.dumps(remaining, sort_keys=True), row['fingerprint']))
        reopened.append(row['fingerprint'])
    return reopened


def list_hypotheses(conn, target, context=None):
    ensure_schema(conn)
    query = 'SELECT fingerprint,dimension_json,status,reason,metadata_json,blockers_json,validation_id,revision FROM web_hypotheses WHERE target_key=?'
    args = [digest(canonical_target(target))]
    if context is not None:
        query += ' AND context_key=?'
        args.append(context)
    rows = [{**json.loads(d), **json.loads(m), 'fingerprint': k, 'status': s, 'reason': r,
             'blockers': json.loads(b), 'validation_id': v, 'revision': rev}
            for k, d, s, r, m, b, v, rev in conn.execute(query, args)]
    return sorted(rows, key=lambda r: (priority(r), r['fingerprint']))


def observe_surface(conn, record, observation_id, classes):
    """New fields/objects/state yield children; replaying the same observation dedups."""
    params = record.get('params') or [{'name': '', 'in': 'query'}]
    keys = []
    for kind in classes:
        for param in params:
            row = {**record, 'vuln_class': kind, 'observation_id': observation_id,
                   'param': param.get('name') or '', 'carrier': param.get('in') or 'query',
                   'observation_quality': 3 if record.get('request_state') == 'observed_request' else 1}
            keys.append(observe(conn, record['target'], row))
    return keys


def invalidate(conn, key):
    """Downgrade a cached terminal projection when its verifier loses evidence."""
    conn.execute("UPDATE web_hypotheses SET status='inconclusive',reason='evidence_unavailable',revision=revision+1 "
                 "WHERE fingerprint=? AND status IN ('confirmed','tested_no_violation')", (key,))
