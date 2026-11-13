"""Synthetic UI controls exercise runtime traversal without Chromium or sockets."""
import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from feature_frontier import UnifiedFrontier  # noqa: E402
from runtime_feature_crawl import actions_for, explore_features  # noqa: E402

BASE = 'https://owned.test/allowed/'


class FeaturePage:
    url = BASE

    def __init__(self):
        self.controls = [
            {'id': 'open-menu', 'safe': True, 'tag': 'button', 'role': 'button', 'expanded': 'false'},
            {'id': 'search-filter', 'safe': True, 'tag': 'select', 'options': ['all', 'mine'], 'value': 'all'},
            {'id': 'delete-account', 'safe': True, 'tag': 'button', 'label': 'Delete account'},
            {'id': 'unknown', 'safe': False, 'tag': 'button'},
        ]
        self.calls, self.operations = [], []

    def evaluate(self, script):
        return copy.deepcopy(self.controls)

    def click(self, selector, **kwargs):
        control_id = json.loads(selector[4:-1])
        self.calls.append(control_id)
        control = next(c for c in self.controls if c['id'] == control_id)
        if control_id == 'open-menu':
            control['expanded'] = 'true'
            self.controls.append({'id': 'reports-tab', 'safe': True, 'tag': 'button',
                                  'role': 'tab', 'selected': 'false'})
            self.operations.append('GET ' + BASE + 'api/menu')
        else:
            control['selected'] = 'true'
            self.operations.append('GET ' + BASE + 'api/reports')

    def select_option(self, selector, value):
        self.calls.append('filter:' + value)
        next(c for c in self.controls if c['tag'] == 'select')['value'] = value
        self.operations.append('GET ' + BASE + 'api/search')

    def harvest(self):
        operations, self.operations = self.operations, []
        return operations


def test_menu_tab_and_filter_operations_are_discovered_and_related_to_states():
    page = FeaturePage()
    queue = UnifiedFrontier(BASE, lambda _: True, 'member-a')
    assert explore_features(page, queue, 10, page.harvest, lambda: None) == 3
    assert page.calls == ['open-menu', 'filter:mine', 'reports-tab']
    features = queue.snapshot()['feature_map']
    assert {f['action'] for f in features} == {'menu', 'tab', 'filter'}
    assert all(f['identity'] == 'member-a' and f['operation_yield'] == 1 for f in features)
    assert {op for f in features for op in f['operations']} == {
        'GET ' + BASE + 'api/menu', 'GET ' + BASE + 'api/search', 'GET ' + BASE + 'api/reports'}
    assert explore_features(page, queue, 10, page.harvest, lambda: None) == 0


def test_action_budget_exposes_unspent_controls_and_can_continue():
    page = FeaturePage()
    queue = UnifiedFrontier(BASE, lambda _: True)
    assert explore_features(page, queue, 1, page.harvest, lambda: None) == 1
    assert len(queue.snapshot()['continuation_queue']) == 2
    assert explore_features(page, queue, 10, page.harvest, lambda: None) == 2
    assert len(page.calls) == 3


def test_zero_action_budget_still_exposes_continuation():
    page = FeaturePage()
    queue = UnifiedFrontier(BASE, lambda _: True)
    assert explore_features(page, queue, 0, page.harvest, lambda: None) == 0
    assert len(queue.pending('ui')) == 2 and not page.calls


@pytest.mark.parametrize('label', ['Purchase', 'PAY', 'submit', 'Save', 'logout', 'revoke', 'Reset'])
def test_unknown_or_mutating_controls_are_never_operated(label):
    controls = [{'id': 'safe-looking', 'safe': True, 'tag': 'button', 'label': label},
                {'id': 'unclassified', 'safe': False, 'tag': 'button'}]
    assert not actions_for(controls)


def test_stop_before_action_preserves_pending_work_without_clicking():
    page = FeaturePage()
    queue = UnifiedFrontier(BASE, lambda _: True)
    explore_features(page, queue, 0, page.harvest, lambda: None)
    def stop():
        raise RuntimeError('http_429')
    with pytest.raises(RuntimeError, match='http_429'):
        explore_features(page, queue, 10, page.harvest, stop)
    assert not page.calls and len(queue.pending('ui')) == 2


def test_hidden_pending_control_does_not_starve_visible_work():
    page = FeaturePage()
    queue = UnifiedFrontier(BASE, lambda _: True)
    explore_features(page, queue, 0, page.harvest, lambda: None)
    page.controls = [c for c in page.controls if c['id'] != 'open-menu']
    assert explore_features(page, queue, 1, page.harvest, lambda: None) == 1
    assert page.calls == ['filter:mine']
    assert any(item['sources'] == ['ui-menu'] for item in queue.pending('ui'))
