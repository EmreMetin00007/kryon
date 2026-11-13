#!/usr/bin/env python3
"""WS7: expiring run/session-bound test objects and hashed lifecycle evidence."""
from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import time
from urllib.parse import urlsplit, urlunsplit

CREDENTIAL_HEADERS = {'authorization', 'cookie', 'x-api-key', 'api-key'}
TRANSITIONS = {
    'sealed': {'pre_state', 'cleanup_failed', 'unknown'},
    'pre_state': {'experiment', 'cleanup_failed', 'unknown'},
    'experiment': {'post_state', 'cleanup_failed', 'unknown'},
    'post_state': {'torn_down', 'cleanup_failed', 'unknown'},
    'cleanup_failed': {'torn_down', 'unknown'},
    'unknown': {'torn_down', 'cleanup_failed'}, 'torn_down': set(),
}


class WriteSetError(Exception):
    pass


def fingerprint_credentials(headers):
    values = [f'{str(k).lower()}:{v}' for k, v in (headers or {}).items()
              if str(k).lower() in CREDENTIAL_HEADERS and isinstance(v, str) and v]
    return hashlib.sha256('|'.join(sorted(values)).encode()).hexdigest() if values else ''


def canonical_url(url):
    p = urlsplit(str(url or ''))
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password or p.fragment:
        raise WriteSetError('absolute object URL without credentials/fragment required')
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or '/', p.query, ''))


def object_key(url):
    return hashlib.sha256(canonical_url(url).encode()).hexdigest()


def origin_of(url):
    p = urlsplit(canonical_url(url))
    return f'{p.scheme}://{p.netloc}'


def _connect(db_path):
    os.makedirs(os.path.dirname(db_path) or '.', exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute('''CREATE TABLE IF NOT EXISTS sealed_objects (
        object_key TEXT PRIMARY KEY, object_url TEXT NOT NULL,
        identity_label TEXT NOT NULL, run_fingerprints TEXT NOT NULL,
        task_ref TEXT NOT NULL, state TEXT NOT NULL, created_at REAL NOT NULL,
        expires_at REAL NOT NULL)''')
    columns = {r[1] for r in conn.execute('PRAGMA table_info(sealed_objects)')}
    for name, sql_type in [('run_id', 'TEXT'), ('session_id', 'TEXT'),
                           ('origin', 'TEXT'), ('test_account', 'INTEGER')]:
        if name not in columns:
            conn.execute(f'ALTER TABLE sealed_objects ADD COLUMN {name} {sql_type}')
    conn.execute('''CREATE TABLE IF NOT EXISTS write_lifecycle (
        id INTEGER PRIMARY KEY, object_key TEXT NOT NULL, run_id TEXT NOT NULL,
        session_id TEXT NOT NULL, phase TEXT NOT NULL, evidence_hash TEXT NOT NULL,
        recorded_at REAL NOT NULL)''')
    conn.commit()
    return conn


def default_db_path(cco_home):
    return os.path.join(cco_home, 'write_set.db')


def _digest(evidence):
    if evidence is None or evidence == '' or evidence == {}:
        raise WriteSetError('lifecycle evidence required')
    return hashlib.sha256(json.dumps(evidence, sort_keys=True, allow_nan=False).encode()).hexdigest()


def seal_object(db_path, *, object_url, identity_label, run_fingerprints,
                task_ref, run_id=None, session_id=None, test_account=False,
                ownership_evidence=None, ttl_seconds=600, now=None, max_per_task=None):
    if not run_id or not session_id:
        raise WriteSetError('run_id and session_id required')
    if test_account is not True or not identity_label or not task_ref:
        raise WriteSetError('declared test account and task required')
    fps = sorted(set(run_fingerprints))
    if not fps or any(not isinstance(fp, str) or not fp for fp in fps):
        raise WriteSetError('run credential fingerprints required')
    digest = _digest(ownership_evidence)
    now = time.time() if now is None else float(now)
    if not math.isfinite(now):
        raise WriteSetError('finite seal time required')
    if not 0 < float(ttl_seconds) <= 86400:
        raise WriteSetError('seal TTL must be in (0, 86400]')
    url = canonical_url(object_url)
    key = object_key(url)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        if conn.execute('SELECT 1 FROM sealed_objects WHERE object_key=?', (key,)).fetchone():
            raise WriteSetError('cross_run_rejected: object already registered; use a fresh fixture')
        if max_per_task is not None:
            count = conn.execute(
                "SELECT COUNT(*) FROM sealed_objects WHERE task_ref=? AND run_id=? AND state!='torn_down'",
                (task_ref, run_id)).fetchone()[0]
            if count >= int(max_per_task):
                raise WriteSetError('task creation cap reached')
        conn.execute('''INSERT INTO sealed_objects
            (object_key,object_url,identity_label,run_fingerprints,task_ref,state,
             created_at,expires_at,run_id,session_id,origin,test_account)
            VALUES (?,?,?,?,?,'sealed',?,?,?,?,?,1)''',
            (key, url, identity_label, json.dumps(fps), task_ref, now,
             now + float(ttl_seconds), run_id, session_id, origin_of(url)))
        for phase in ('setup', 'own'):
            conn.execute('INSERT INTO write_lifecycle VALUES (NULL,?,?,?,?,?,?)',
                         (key, run_id, session_id, phase, digest, now))
        conn.commit()
    finally:
        conn.close()
    return key


def inspect_object(db_path, object_url):
    if not os.path.exists(db_path):
        return None
    conn = _connect(db_path)
    try:
        row = conn.execute('SELECT * FROM sealed_objects WHERE object_key=?',
                           (object_key(object_url),)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result.pop('run_fingerprints')
        result['lifecycle'] = [dict(r) for r in conn.execute(
            'SELECT phase,evidence_hash,recorded_at FROM write_lifecycle WHERE object_key=? ORDER BY id',
            (object_key(object_url),))]
        return result
    finally:
        conn.close()


def is_sealed(db_path, object_url, now=None):
    row = inspect_object(db_path, object_url)
    now = time.time() if now is None else float(now)
    return bool(row and row['run_id'] and row['session_id'] and row['test_account'] == 1
                and row['state'] in {'sealed', 'pre_state', 'experiment', 'post_state'}
                and now < row['expires_at'])


def mutation_permitted(db_path, object_url, caller_fingerprint, now=None, *, run_id=None, session_id=None):
    if not os.path.exists(db_path):
        return False, 'object is not sealed'
    conn = _connect(db_path)
    try:
        row = conn.execute('SELECT * FROM sealed_objects WHERE object_key=?',
                           (object_key(object_url),)).fetchone()
    finally:
        conn.close()
    if row is None:
        return False, 'object is not sealed'
    if not run_id or not session_id or (run_id, session_id) != (row['run_id'], row['session_id']):
        return False, 'cross_run_rejected'
    now = time.time() if now is None else float(now)
    if row['test_account'] != 1 or row['origin'] != origin_of(object_url):
        return False, 'test account/origin binding missing'
    if now >= row['expires_at']:
        return False, 'seal expired'
    if not caller_fingerprint or caller_fingerprint not in json.loads(row['run_fingerprints']):
        return False, 'caller identity is not part of the sealing run'
    if row['state'] not in {'pre_state', 'experiment'}:
        return False, f"object state is {row['state']}"
    return True, 'sealed'


def mark_state(db_path, object_url, state, *, run_id=None, session_id=None, evidence=None, now=None):
    digest = _digest(evidence)
    conn = _connect(db_path)
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT * FROM sealed_objects WHERE object_key=?',
                           (object_key(object_url),)).fetchone()
        if not row or not run_id or not session_id or (run_id, session_id) != (row['run_id'], row['session_id']):
            raise WriteSetError('cross_run_rejected')
        if state not in TRANSITIONS.get(row['state'], set()):
            raise WriteSetError(f"invalid lifecycle transition {row['state']} -> {state}")
        conn.execute('UPDATE sealed_objects SET state=? WHERE object_key=?', (state, object_key(object_url)))
        conn.execute('INSERT INTO write_lifecycle VALUES (NULL,?,?,?,?,?,?)',
                     (object_key(object_url), run_id, session_id, state, digest,
                      time.time() if now is None else float(now)))
        conn.commit()
    finally:
        conn.close()
