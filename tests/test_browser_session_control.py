"""Bound session controls use synthetic responses and the real encrypted fixture store."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
for folder in ('scripts', 'mcp-servers/mcp-memory-server'):
    sys.path.insert(0, str(ROOT / folder))
from browser_session_control import check_bound_session  # noqa: E402
from cco_surface_core import session_store  # noqa: E402

TARGET = 'https://owned.test/allowed/'
IDENTITY = 'member-a'


class Response:
    def __init__(self, status, body, location=''):
        self.status, self.payload = status, body
        self.headers, self.disposed = {'location': location}, False

    def body(self):
        return self.payload

    def dispose(self):
        self.disposed = True


class Engine:
    accounts_campaign_requests = True

    def __init__(self, allowed=True):
        self.allowed, self.calls = allowed, []

    def validate_wire_invocation(self, tool, args):
        self.calls.append((tool, args))
        return {'allowed': self.allowed}


@pytest.fixture
def bound(tmp_path, monkeypatch):
    monkeypatch.setenv('CCO_HOME', str(tmp_path / 'home'))
    session_store.put_session(TARGET, IDENTITY, headers={'Authorization': 'Bearer synthetic'},
                              cookies={'sid': 'synthetic-cookie'}, check_url=TARGET + 'session-check',
                              marker='member-a')
    session_store.refresh_status(TARGET, IDENTITY, lambda *_: (200, 'member-a'))
    snapshot = session_store.verified_session(TARGET, IDENTITY)
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'in_scope': [{'asset': TARGET}], 'allow_loopback': False,
                                 'allow_osint': False, 'allow_public_labs': False}))
    monkeypatch.setenv('CCO_SCOPE_FILE', str(scope))
    return snapshot


def run_control(snapshot, response, engine=None):
    calls = []
    def get(url, **kwargs):
        calls.append((url, kwargs))
        return response
    engine = engine or Engine()
    result = check_bound_session(SimpleNamespace(request=SimpleNamespace(get=get)), engine,
                                 'kali-tools_crawl_web_surface', TARGET, IDENTITY, snapshot)
    return result, calls, engine


def test_fresh_control_is_one_gated_redirect_disabled_get_and_updates_attestation(bound):
    previous = bound['check_id']
    response = Response(200, b'member-a')
    result, calls, engine = run_control(bound, response)
    assert result['status'] == 'fresh' and len(calls) == len(engine.calls) == 1
    assert calls[0][0] == TARGET + 'session-check'
    assert calls[0][1]['max_redirects'] == 0
    assert calls[0][1]['headers']['Cookie'] == 'sid=synthetic-cookie'
    assert response.disposed and bound['check_id'] != previous
    assert session_store.same_verified_session(TARGET, IDENTITY, bound)
    assert 'synthetic' not in str(result)


@pytest.mark.parametrize('status,location,expected', [
    (401, '', 'expired'), (403, '', 'expired'), (302, '/login', 'expired'),
    (429, '', 'rate_limited'), (502, '', 'stale'), (503, '', 'stale'), (504, '', 'stale'),
])
def test_control_status_cannot_be_overridden_by_marker(bound, status, location, expected):
    response = Response(status, b'member-a', location)
    result, calls, _ = run_control(bound, response)
    assert result['status'] == expected and len(calls) == 1 and response.disposed
    assert session_store.verified_session(TARGET, IDENTITY) is None
    if status in {502, 503, 504}:
        assert result['reason'] == 'service_degradation'


def test_rotated_binding_never_reads_or_sends_previous_secret(bound):
    session_store.put_session(TARGET, IDENTITY, headers={'Authorization': 'Bearer replacement'})
    result, calls, engine = run_control(bound, Response(200, b'member-a'))
    assert result['reason'] == 'session_binding_unavailable' and not calls and not engine.calls


def test_policy_denial_sends_no_request(bound):
    result, calls, _ = run_control(bound, Response(200, b'member-a'), Engine(False))
    assert result['status'] == 'blocked' and not calls


def test_oversized_marker_response_fails_closed_and_disposes(bound):
    response = Response(200, b'member-a' + b'x' * 65536)
    result, calls, _ = run_control(bound, response)
    assert result['status'] == 'stale' and len(calls) == 1 and response.disposed


def test_missing_marker_routes_to_session_recovery(bound):
    result, calls, _ = run_control(bound, Response(200, b'anonymous'))
    assert result['reason'] == 'marker_missing' and len(calls) == 1


@pytest.mark.parametrize('check_url', ['https://external.test/session-check', TARGET + '../outside',
                                      TARGET + 'logout'])
def test_unsafe_check_url_does_not_send_control(bound, check_url):
    session_store.put_session(TARGET, IDENTITY, headers={'Authorization': 'Bearer synthetic'},
                              check_url=check_url, marker='member-a')
    # Synthetic transport establishes fixture freshness only; the production
    # control must independently reject scope/origin/destructive-path errors.
    session_store.refresh_status(TARGET, IDENTITY, lambda *_: (200, 'member-a'))
    snapshot = session_store.verified_session(TARGET, IDENTITY)
    result, calls, _ = run_control(snapshot, Response(200, b'member-a'))
    assert result['status'] != 'fresh' and not calls
