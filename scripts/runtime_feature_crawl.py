"""Deterministic browser feature traversal, using existing request interception.

Only semantic view controls with an existing panel are operated. Forms,
submit buttons, arbitrary buttons and keyboard actions remain inventory.
"""
from __future__ import annotations

import json
import re

from feature_frontier import digest, metadata_url


CONTROLS_JS = """() => {
  const controls = [];
  for (const el of document.querySelectorAll('[role=tab], button[aria-controls], select[data-cco-readonly]')) {
    const rect = el.getBoundingClientRect();
    if (!rect.width || !rect.height || el.disabled || !el.id) continue;
    const panel = document.getElementById(el.getAttribute('aria-controls') || '');
    const role = el.getAttribute('role') || '';
    const tag = el.tagName.toLowerCase();
    const filter = tag === 'select' && el.getAttribute('data-cco-readonly') === 'true';
    const safe = !el.closest('form') && !el.getAttribute('href') &&
      (filter || (panel && ((role === 'tab' && panel.getAttribute('role') === 'tabpanel') ||
        (tag === 'button' && el.type === 'button' && el.hasAttribute('aria-expanded') &&
         ['menu','tablist','region'].includes(panel.getAttribute('role'))))));
    controls.push({id: el.id, role, tag, safe,
      label: (el.textContent || '').trim().slice(0,80),
      selected: el.getAttribute('aria-selected'), expanded: el.getAttribute('aria-expanded'),
      options: filter ? Array.from(el.options).filter(o => !o.disabled).map(o => o.value) : [],
      value: filter ? el.value : ''});
  }
  return controls;
}"""


def screen_state(controls):
    return sorted((c['id'], c.get('selected'), c.get('expanded'), c.get('value')) for c in controls)


def actions_for(controls):
    actions = []
    for control in controls:
        if not control.get('safe') or re.search(
                r'delete|remove|logout|sign.?out|purchase|pay|submit|save|reset|revoke|destroy',
                str(control.get('label', '')) + ' ' + str(control.get('id', '')), re.I):
            continue
        if control.get('tag') == 'select':
            actions.extend({'id': control['id'], 'value': value, 'kind': 'filter'}
                           for value in control.get('options', []) if value != control.get('value'))
        elif control.get('selected') != 'true' and control.get('expanded') != 'true':
            actions.append({'id': control['id'], 'kind': 'tab' if control.get('role') == 'tab' else 'menu'})
    return actions


def explore_features(page, frontier, max_actions, harvest, ensure_active, wait_ms=0):
    """Harvest every reached screen; never replay a control on the same shell.

    Each action has a ledger entry, including unspent continuation work. The
    operation yield records observed requests even when the DOM is unchanged.
    """
    fired = set()
    used = 0
    while True:
        ensure_active()
        controls = page.evaluate(CONTROLS_JS)
        screen = screen_state(controls)
        frontier.visit(page.url, screen)
        # The selected filter already belongs to a harvested screen. Record
        # each value separately so other options remain discoverable, while
        # returning to a previously observed value does not spend the budget.
        for control in controls:
            if control.get('safe') and control.get('tag') == 'select':
                action = {'id': control['id'], 'value': control.get('value'), 'kind': 'filter'}
                item = frontier.add(page.url, source='ui-filter', kind='ui',
                                    screen=digest([page.url, frontier.identity, action]))
                frontier.finish(item)
        for action in actions_for(controls):
            action_key = digest([page.url, frontier.identity, action])
            if action_key in fired:
                continue
            frontier.add(page.url, source='ui-' + action['kind'], kind='ui', screen=action_key)
        candidates = [item for item in frontier.pending('ui') if item['url'] == page.url]
        if not candidates or used >= max(0, int(max_actions)):
            break
        available_actions = {digest([page.url, frontier.identity, a]): a for a in actions_for(controls)}
        target_pair = None
        for item in candidates:
            if item['screen'] in available_actions:
                target_pair = (item, available_actions[item['screen']])
                break
        if target_pair is None:
            break
        item, action = target_pair
        fired.add(item['screen'])
        item['status'] = 'running'
        before_page = page.url
        selector = '[id=' + json.dumps(action['id']) + ']'
        if action['kind'] == 'filter':
            page.select_option(selector, action['value'])
        else:
            page.click(selector, timeout=5000)
        used += 1
        if wait_ms:
            page.wait_for_timeout(wait_ms)
        ensure_active()
        operations = harvest()
        after = screen_state(page.evaluate(CONTROLS_JS))
        frontier.visit(page.url, after, operations)
        frontier.finish(item)
        frontier.features.append({'page': metadata_url(before_page), 'identity': frontier.identity,
                                  'action': action['kind'], 'control': action['id'],
                                  'from_screen': digest(screen), 'to_screen': digest(after),
                                  'operations': list(dict.fromkeys(operations)),
                                  'operation_yield': len(set(operations))})
    return used
