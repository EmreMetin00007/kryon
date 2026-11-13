"""Expected authorization restrictions must not masquerade as session loss."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from crawl_auth import CrawlAuthBoundary, login_redirect  # noqa: E402

CHECK = 'https://owned.test/allowed/session-check'
RESTRICTED = 'https://owned.test/allowed/admin?token=synthetic-secret'


@pytest.mark.parametrize('status', [401, 403])
def test_anonymous_restriction_does_not_request_session_recovery(status):
    boundary = CrawlAuthBoundary(CHECK)
    assert not boundary.observe(RESTRICTED, status)
    assert not boundary.resolve(lambda: pytest.fail('anonymous identity has no session control'))
    assert boundary.summary()['session_checks'] == 0
    assert not boundary.summary()['session_recovery']
    assert 'synthetic-secret' not in str(boundary.summary())


@pytest.mark.parametrize('status', [401, 403, 302])
def test_restricted_endpoint_requires_one_fresh_bound_control(status):
    boundary = CrawlAuthBoundary(CHECK, authenticated=True)
    assert not boundary.observe(RESTRICTED, status, '/login' if status == 302 else '')
    boundary.observe(RESTRICTED, status, '/login' if status == 302 else '')
    assert boundary.pending
    assert not boundary.resolve(lambda: {'status': 'fresh'})
    assert not boundary.pending
    assert len(boundary.restrictions) == 1 and boundary.checks == 1
    assert not boundary.resolve(lambda: pytest.fail('resolved restrictions must not re-probe'))


@pytest.mark.parametrize('result,reason,recovery', [
    ({'status': 'expired'}, 'session_expired', True),
    ({'status': 'stale', 'reason': 'marker_missing'}, 'session_expired', True),
    ({'status': 'rate_limited'}, 'http_429', False),
    ({'status': 'stale', 'reason': 'service_degradation'}, 'service_degradation', False),
    ({'status': 'unknown'}, 'session_check_required', False),
])
def test_failed_control_stops_with_specific_recovery_route(result, reason, recovery):
    boundary = CrawlAuthBoundary(CHECK, authenticated=True)
    boundary.observe(RESTRICTED, 403)
    assert boundary.resolve(lambda: result) == reason
    assert boundary.summary()['session_recovery'] is recovery
    assert boundary.checks == 1


@pytest.mark.parametrize('status,reason', [(401, 'http_401'), (403, 'http_403'),
                                          (302, 'login_redirect'), (429, 'http_429'),
                                          (502, 'service_degradation'), (503, 'service_degradation'),
                                          (504, 'service_degradation')])
def test_primary_session_failure_or_degradation_stops_immediately(status, reason):
    boundary = CrawlAuthBoundary(CHECK, authenticated=True)
    assert boundary.observe(CHECK, status, '/login' if status == 302 else '') == reason
    assert boundary.resolve(lambda: pytest.fail('hard stop must not generate a control')) == reason


def test_control_exception_fails_closed():
    boundary = CrawlAuthBoundary(CHECK, authenticated=True)
    boundary.observe(RESTRICTED, 401)
    assert boundary.resolve(lambda: 1 / 0) == 'session_check_required'


@pytest.mark.parametrize('location', ['/login', '/%256Cogin', '../signin', '/sso/start'])
def test_encoded_login_redirect_detection(location):
    assert login_redirect(CHECK, location)


def test_nonlogin_redirect_does_not_invalidate_session():
    boundary = CrawlAuthBoundary(CHECK, authenticated=True)
    assert not boundary.observe(RESTRICTED, 302, '/allowed/home')
    assert not boundary.pending
