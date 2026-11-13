"""Offline source/identity/continuation contracts for P3 discovery."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from feature_frontier import UnifiedFrontier, metadata_url, origin  # noqa: E402

BASE = 'https://owned.test/allowed/'


def frontier(identity='anonymous'):
    return UnifiedFrontier(BASE, lambda url: url.startswith(BASE), identity)


def test_all_sources_merge_without_losing_provenance():
    queue = frontier()
    for source in ('html', 'js', 'openapi', 'captured-traffic', 'gau', 'wayback', 'runtime-xhr'):
        queue.add_records([{'url': BASE + 'search?q=value', 'sources': [source]}])
    assert len(queue.items) == 1
    assert next(iter(queue.items.values()))['sources'] == [
        'html', 'js', 'openapi', 'captured-traffic', 'gau', 'wayback', 'runtime-xhr']


def test_bundle_budget_retains_every_unspent_item_after_sixteen():
    queue = frontier()
    queue.add_records([{'url': BASE + f'chunk-{i}.js'} for i in range(40)])
    for _ in range(16):
        queue.finish(queue.take('bundle'))
    snapshot = queue.snapshot()
    assert len(snapshot['frontier']) == 40
    assert len(snapshot['continuation_queue']) == 24
    assert queue.take('bundle')['url'].endswith('chunk-16.js')


@pytest.mark.parametrize('url', [
    'https://external.test/api', 'https://owned.test:444/allowed/api',
    'http://owned.test/allowed/api', 'https://owned.test/outside',
])
def test_discovery_never_expands_active_scope(url):
    queue = frontier()
    queue.add(url, source='runtime-xhr')
    assert not queue.pending()
    assert queue.snapshot()['external_sources'][0]['reason'] == 'requires_scope_approval'


@pytest.mark.parametrize('method', ['POST', 'PUT', 'PATCH', 'DELETE'])
def test_mutating_operations_are_inventory_only(method):
    queue = frontier()
    item = queue.add(BASE + 'orders', source='openapi', method=method)
    assert item['reason'] == 'inventory_only'
    assert not queue.pending()


def test_template_and_nonexecutable_source_need_request_context():
    queue = frontier()
    assert queue.add(BASE + 'orders/{id}', source='openapi')['reason'] == 'requires_request_context'
    assert queue.add(BASE + 'unknown', source='form', executable=False)['reason'] == 'inventory_only'


def test_anonymous_and_bound_identity_have_distinct_state_keys():
    anon, member = frontier(), frontier('member-a')
    anon.visit(BASE, [('tab', 'true')])
    member.visit(BASE, [('tab', 'true')])
    assert set(anon.visits).isdisjoint(member.visits)
    assert anon.visit(BASE, [('tab', 'false')])
    assert not anon.visit(BASE, [('tab', 'false')])
    assert len(anon.visits) == 2


def test_repeat_screen_retains_observed_operation_yield():
    queue = frontier()
    queue.visit(BASE, ['unchanged'])
    assert not queue.visit(BASE, ['unchanged'], ['GET /api/menu', 'GET /api/menu'])
    assert next(iter(queue.visits.values()))['operation_yield'] == 1


def test_public_frontier_redacts_query_and_screen_values():
    queue = frontier('member-a')
    queue.add(BASE + 'search?token=synthetic-secret', source='xhr')
    queue.visit(BASE + '?token=synthetic-secret', ['synthetic-filter-value'])
    rendered = json.dumps(queue.snapshot())
    assert 'synthetic-secret' not in rendered and 'synthetic-filter-value' not in rendered
    assert 'token' in rendered


@pytest.mark.parametrize('url', ['file:///tmp/a', 'javascript:alert(1)',
                                     'https://user:password@owned.test/allowed/',
                                     'https://owned.test:bad/allowed/'])
def test_invalid_or_credential_bearing_origins_are_rejected(url):
    assert origin(url) is None
    assert frontier().add(url, source='html') is None


def test_metadata_retains_empty_and_repeated_parameter_names():
    url = metadata_url(BASE + '?q=&q=second&token=secret')
    assert url.count('q=') == 2 and 'token=' in url
    assert 'second' not in url and 'secret' not in url
