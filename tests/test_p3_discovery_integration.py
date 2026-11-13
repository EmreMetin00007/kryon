"""Real discovery/crawl entry points with in-memory transports and browser doubles."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest

from conftest import load_server
from test_surface_crawl_policy import (
    FakePlaywright, Page, Request, Route, checked_session, setup as crawl_setup,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from cco_surface_core import crawl  # noqa: E402
from cco_surface_core.wire import scoped_surface_requests  # noqa: E402

BASE = 'https://owned.test/allowed/'


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    scope = tmp_path / 'scope.json'
    scope.write_text(json.dumps({'in_scope': [{'asset': 'https://owned.test/'}],
                                 'allow_loopback': False, 'allow_osint': False,
                                 'allow_public_labs': False}))
    monkeypatch.setenv('CCO_SCOPE_FILE', str(scope))
    monkeypatch.setenv('CCO_WORKDIR', str(tmp_path))
    kali = load_server('kali-tools')
    calls, bodies = [], {}
    def get(url, **kwargs):
        calls.append(url)
        body = bodies.get(url, '')
        return SimpleNamespace(status_code=200 if url in bodies else 404,
                               url=url, text=body, content=body.encode(), cookies=[],
                               headers={'Content-Type': 'text/html' if url == BASE else 'application/javascript'})
    monkeypatch.setattr(kali.requests, 'get', get)
    def run(**kwargs):
        with scoped_surface_requests(lambda *_: (True, 'synthetic-fixture'), BASE):
            return json.loads(kali.discover_web_surface(BASE, **kwargs))
    return run, bodies, calls


def test_entry_point_processes_more_than_sixteen_bundles(discovery):
    run, bodies, calls = discovery
    bundles = [BASE + f'chunk-{i}.js' for i in range(24)]
    bodies[BASE] = ''.join(f'<script src="{url}"></script>' for url in bundles)
    bodies.update({url: f'fetch("/allowed/api/feature-{i}");' for i, url in enumerate(bundles)})
    result = run(probe_limit=30)
    assert not result.get('stop_reason')
    assert set(bundles).issubset(calls)
    assert all(calls.count(url) == 1 for url in bundles)
    assert any('/feature-23' in item['url'] for item in result['frontier'])


def test_source_budget_preserves_lazy_imports_and_unspent_bundles(discovery):
    run, bodies, calls = discovery
    bodies[BASE] = '<script src="main.js"></script><script src="second.js"></script>'
    bodies[BASE + 'main.js'] = 'import("./lazy.mjs"); fetch("/allowed/api/menu");'
    bodies[BASE + 'second.js'] = 'fetch("/allowed/api/second");'
    bodies[BASE + 'lazy.mjs'] = 'fetch("/allowed/api/lazy");'
    result = run(probe_limit=1, mode='passive')
    pending = {item['url'] for item in result['continuation_queue'] if item['kind'] == 'bundle'}
    assert pending == {BASE + 'second.js', BASE + 'lazy.mjs'}
    assert BASE + 'main.js' in calls and BASE + 'lazy.mjs' not in calls


def test_lazy_imports_are_processed_in_the_same_frontier(discovery):
    run, bodies, calls = discovery
    bodies[BASE] = '<script src="main.js"></script>'
    bodies[BASE + 'main.js'] = 'import("./lazy.mjs");'
    bodies[BASE + 'lazy.mjs'] = 'fetch("/allowed/api/lazy");'
    result = run(probe_limit=4, mode='passive')
    assert BASE + 'lazy.mjs' in calls
    assert any('/api/lazy' in item['url'] for item in result['frontier'])


def test_external_html_sources_remain_inventory_and_are_never_requested(discovery):
    run, bodies, calls = discovery
    bodies[BASE] = '<script src="https://cdn.external.test/lazy.js"></script><a href="https://other.test/api">Other</a>'
    result = run(probe_limit=4)
    assert {urlsplit(item['url']).hostname for item in result['external_sources']} == {
        'cdn.external.test', 'other.test'}
    assert all(urlsplit(url).hostname == 'owned.test' for url in calls)


def test_active_probe_budget_preserves_every_unspent_route(discovery):
    run, bodies, calls = discovery
    bodies[BASE] = ''.join(f'<a href="view-{i}">View</a>' for i in range(12))
    result = run(probe_limit=2)
    routes = [item for item in result['continuation_queue'] if '/view-' in item['url']]
    assert len({item['url'] for item in routes}) == 10
    assert sum('/view-' in url for url in calls) == 2


def test_browser_receives_compiled_source_records(discovery, monkeypatch):
    run, bodies, _ = discovery
    bodies[BASE] = '<script src="main.js"></script>'
    bodies[BASE + 'main.js'] = 'fetch("/allowed/api/menu");'
    received = []
    def browser(url, **kwargs):
        received.extend(kwargs['source_records'])
        return {'ok': True, 'records': [], 'feature_map': [{'control': 'reports-tab', 'identity': 'anonymous'}]}
    kali = sys.modules['cco_kali_tools']
    monkeypatch.setattr(kali, 'crawl_site', browser)
    result = run(probe_limit=4, include_browser=True)
    assert any('/api/menu' in row['url'] for row in received)
    assert result['feature_map'][0]['control'] == 'reports-tab'


def install_feature_browser(monkeypatch, status=200, restricted_status=200):
    fake = FakePlaywright(status)
    monkeypatch.setattr(crawl, 'sync_playwright', lambda: fake)
    monkeypatch.setattr(Page, 'evaluate', lambda self, script: [
        {'id': 'menu', 'safe': True, 'tag': 'button', 'expanded': 'true' if getattr(self, 'clicked', False) else 'false'}])
    def click(self, selector, **kwargs):
        self.clicked = True
        request = Request(BASE + 'api/menu', 'GET', 'fetch')
        route = Route(request)
        self.context.route_handler(route)
        self.context.observed.append(route)
        if route.action != 'continued':
            return
        response = SimpleNamespace(status=restricted_status, url=request.url, headers={}, request=request)
        self.context.handlers['response'](response)
        self.listeners['response'](response)
    monkeypatch.setattr(Page, 'click', click, raising=False)
    original = fake.new_context
    def new_context(**kwargs):
        context = original(**kwargs)
        context.control_calls = []
        def get(url, **kwargs):
            context.control_calls.append(url)
            return SimpleNamespace(status=200, headers={}, body=lambda: b'member-a', dispose=lambda: None)
        context.request = SimpleNamespace(get=get)
        return context
    monkeypatch.setattr(fake, 'new_context', new_context)
    return fake


def test_real_crawler_harvests_feature_xhr_and_relates_identity(crawl_setup):
    install_feature_browser(crawl_setup)
    target = checked_session()
    result = crawl.crawl_site(target + '/start', wait_ms=0, max_pages=1,
                             session_target=target, identity='member-a', tool_name='hunter_run_web_loop')
    assert result['ok'] and len(result['feature_map']) == 1
    assert result['feature_map'][0]['identity'] == 'member-a'
    assert result['feature_map'][0]['operations'] == ['GET ' + BASE + 'api/menu']
    assert any(item['sources'] == ['runtime-xhr'] for item in result['frontier'])


@pytest.mark.parametrize('status', [401, 403])
def test_real_crawler_restriction_checks_one_bound_control_and_continues(crawl_setup, status):
    fake = install_feature_browser(crawl_setup, restricted_status=status)
    target = checked_session()
    result = crawl.crawl_site(target + '/start', wait_ms=0, max_pages=1,
                             session_target=target, identity='member-a', tool_name='hunter_run_web_loop')
    assert result['ok'] and result['session_checks'] == 1 and not result['session_recovery']
    assert result['authorization_restrictions'][0]['status'] == status
    assert fake.contexts[0].control_calls == [target]


def test_real_crawler_zero_action_budget_exposes_feature_continuation(crawl_setup):
    install_feature_browser(crawl_setup)
    target = checked_session()
    result = crawl.crawl_site(target + '/start', wait_ms=0, max_pages=1, max_actions=0,
                             session_target=target, identity='member-a', tool_name='hunter_run_web_loop')
    assert result['ok'] and not result['feature_map']
    assert any(item['kind'] == 'ui' for item in result['continuation_queue'])
