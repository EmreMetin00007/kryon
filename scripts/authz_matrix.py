"""Offline authorization coverage. Facts and access rules are never inferred from tokens.

Inputs describe operator supplied test accounts and objects. Evidence references
are provenance, not validation receipts; this planner never confirms a finding.
"""
from __future__ import annotations

from object_identity import object_id_key

CATEGORIES = ('owner', 'same_tenant_other_user', 'cross_tenant_user', 'different_role', 'anonymous')
SOURCES = {'operator', 'response_metadata', 'differential_list'}


def identity_fact(actor, field):
    facts = [f for f in actor.get('identity_facts', []) if isinstance(f, dict)
             and f.get('field') == field and f.get('source') in SOURCES
             and isinstance(f.get('evidence'), str) and f['evidence'].strip()
             and isinstance(f.get('value'), str) and f['value'].strip()]
    values = {f['value'] for f in facts}
    return next(iter(values)) if len(values) == 1 else None


def same_principal(owner, other):
    """None means unknown, including different credentials without identity facts."""
    a, b = identity_fact(owner, 'principal'), identity_fact(other, 'principal')
    if not a or not b:
        return None
    # Principal IDs are scoped to an evidenced identity authority/issuer.
    x, y = identity_fact(owner, 'authority'), identity_fact(other, 'authority')
    if not x or not y or x != y:
        return None
    return a == b


def resource_key(resource):
    """The same opaque ID in two tenants or families denotes distinct resources."""
    import json
    return json.dumps([resource['tenant'], resource['family'],
                       object_id_key(resource['resource_id'])], separators=(',', ':'))


def access_expectation(resource, actor, category, field=''):
    """Only a sourced access rule can assert denial; ownership alone cannot."""
    rule = resource.get('access_rule') or {}
    if (rule.get('source') not in SOURCES or not rule.get('evidence')
            or rule.get('visibility') not in {'private', 'public', 'shared'}):
        return 'unknown'
    if category == 'owner':
        return 'allow'
    if rule['visibility'] == 'public':
        return 'allow'
    principal, role = identity_fact(actor, 'principal'), identity_fact(actor, 'role')
    if rule['visibility'] == 'shared':
        if principal in rule.get('shared_principals', []):
            return 'allow'
        return 'unknown'  # Sharing metadata is not an exhaustive deny list.
    denied = rule.get('denied_field_roles', {}).get(field, []) if field else rule.get('denied_roles', [])
    if role and role in denied:
        return 'deny'
    if field:
        return 'unknown'
    if category == 'anonymous':
        return 'deny' if rule.get('authentication_required') is True else 'unknown'
    if resource.get('kind') == 'function':
        return 'unknown'
    return 'deny' if rule.get('owner_only') is True else 'unknown'


def build_identity_matrix(identities, resources):
    """Five explicit groups per test object, with missing coverage kept visible."""
    rows = []
    for resource in resources:
        if resource.get('test_data_only') is not True:
            continue
        owner_name = resource.get('owner_identity')
        owner = identities.get(owner_name) or {}
        groups = {c: [] for c in CATEGORIES}
        if owner.get('test_data_only') is True and identity_fact(owner, 'principal'):
            groups['owner'].append(owner_name)
        for name, actor in identities.items():
            if name == owner_name or actor.get('test_data_only') is not True:
                continue
            if same_principal(owner, actor) is not False:
                continue
            tenant, other_tenant = identity_fact(owner, 'tenant'), identity_fact(actor, 'tenant')
            role, other_role = identity_fact(owner, 'role'), identity_fact(actor, 'role')
            if tenant and other_tenant:
                groups['same_tenant_other_user' if tenant == other_tenant else 'cross_tenant_user'].append(name)
            if role and other_role and role != other_role:
                groups['different_role'].append(name)
        groups['anonymous'] = ['anonymous']
        for category, names in groups.items():
            for name in names or [None]:
                expectation = access_expectation(resource, identities.get(name) or {}, category, resource.get('field', ''))
                actor = identities.get(name) or {}
                reason = ('missing_evidenced_identity' if name is None else
                          'session_unavailable' if name != 'anonymous' and actor.get('session_status') in {'expired', 'stale'} else
                          'access_rule_unavailable' if expectation == 'unknown' else '')
                rows.append({'resource_key': resource_key(resource), 'category': category,
                             'identity': name, 'owner_identity': owner_name,
                             'expectation': expectation, 'status': 'blocked' if reason else 'ready',
                             'reason': reason, 'verdict': 'NOT_TESTED',
                             'test_type': ('authentication_bypass' if category == 'anonymous' else
                                           'bfla' if resource.get('kind') == 'function' else
                                           'field_authorization' if resource.get('field') else 'bola'),
                             'validate_with': 'existing_authz_oracle'})
    return {'matrix': rows, 'missing_coverage': [r for r in rows if r['status'] == 'blocked']}


def block_identity_work(rows, identity):
    for row in rows:
        if (identity in {row.get('identity'), row.get('owner_identity')}
                and (row['status'] in {'ready', 'pending'}
                     or row.get('reason') == 'session_unavailable')):
            blockers = set(row.get('blocked_identities', []))
            blockers.add(identity)
            row.update(status='blocked', reason='session_unavailable',
                       blocked_identities=sorted(blockers))


def resume_identity_work(rows, identity):
    """Release only this session's dependency; all other blockers remain intact."""
    for row in rows:
        if row['status'] != 'blocked' or row.get('reason') != 'session_unavailable':
            continue
        blockers = set(row.get('blocked_identities', [row.get('identity')]))
        if identity not in blockers:
            continue
        blockers.remove(identity)
        if blockers:
            row['blocked_identities'] = sorted(blockers)
        else:
            row.update(status='ready', reason='')
            row.pop('blocked_identities', None)


def object_access_blocked(resource, owner, other):
    """Conservative guard for the legacy oracle handoff, including partial facts."""
    from object_identity import valid_resource_binding
    if not valid_resource_binding(resource):
        return True
    if resource.get('visibility') in {'public', 'shared'}:
        return True
    rule = resource.get('access_rule') or {}
    if rule.get('visibility') in {'public', 'shared'}:
        return True
    if same_principal(owner, other) is True:
        return True
    # When P4 facts are supplied, ambiguous or absent actor facts cannot prove two users.
    if owner.get('identity_facts') or other.get('identity_facts'):
        return same_principal(owner, other) is not False
    return False
