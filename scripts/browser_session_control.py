"""One bounded, policy-gated control for an explicitly bound test identity."""
from __future__ import annotations

from crawl_auth import login_redirect
from feature_frontier import origin


def check_bound_session(context, engine, tool_name, target, identity, snapshot):
    from cco_surface_core import session_store
    from cco_surface_core.normalize import discovery_link_skip_reason
    from policy_engine import ScopeResolver
    from wire_budget import consume_request

    if not target or not identity or not snapshot or not session_store.same_verified_session(target, identity, snapshot):
        return {'status': 'unknown', 'reason': 'session_binding_unavailable'}
    observed = {}

    def get(url, headers, cookies):
        import posixpath
        from urllib.parse import urlsplit, urlunsplit
        parsed = urlsplit(url)
        norm_url = urlunsplit((parsed.scheme, parsed.netloc, posixpath.normpath(parsed.path),
                               parsed.query, parsed.fragment))
        if (origin(url) != origin(target) or not ScopeResolver().permits_url(url)
                or not ScopeResolver().permits_url(norm_url)
                or discovery_link_skip_reason(url)):
            raise PermissionError('session control outside permitted scope')
        if cookies:
            headers['Cookie'] = '; '.join(f'{k}={v}' for k, v in cookies.items())
        decision = engine.validate_wire_invocation(tool_name, {'url': url, 'target': url,
                                                               'method': 'GET', 'headers': headers})
        if not decision.get('allowed'):
            raise PermissionError('session control policy denied')
        allowed, reason = consume_request(engine)
        if not allowed:
            observed['budget_reason'] = reason
            raise PermissionError('session control budget exhausted')
        response = context.request.get(url, headers=headers, timeout=10000, max_redirects=0)
        try:
            observed.update(status=response.status, location=response.headers.get('location', ''))
            # Read only the dedicated test marker response, bounded before text decoding.
            body = response.body()
            if len(body) > 65536:
                raise ValueError('session control response too large')
            return response.status, body.decode('utf-8', errors='replace')
        finally:
            response.dispose()

    result = session_store.refresh_status(target, identity, get)
    status = observed.get('status')
    if status in {401, 403} or (observed.get('location') and login_redirect(
            snapshot.get('check_url', ''), observed['location'])):
        return {'status': 'expired', 'reason': 'session_control_failed'}
    if status in {502, 503, 504}:
        return {'status': 'stale', 'reason': 'service_degradation'}
    if result.get('status') == 'fresh':
        checked = session_store.verified_session(target, identity)
        if checked is None:
            return {'status': 'unknown', 'reason': 'session_changed_during_control'}
        snapshot.clear()
        snapshot.update(checked)
    return result
