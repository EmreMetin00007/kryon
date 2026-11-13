"""Explicit test-resource prerequisites for function and anonymous checks.

Role names, route names and response equality do not establish an access rule.
The operator supplies that rule and a marker from their own test resource.
"""
from __future__ import annotations

import hashlib
import json

from .blind_discovery import _credentials


def session_identity(entry, spec, scope):
    """Restore declarations and credentials from the same attested session."""
    from cco_surface_core.test_resources import resolve_resources
    declared = resolve_resources(entry, spec.get("role"), scope.permits_url)
    headers = dict(entry.get("headers") or {})
    cookies = entry.get("cookies") or {}
    if cookies:
        if any(str(k).lower() == "cookie" for k in headers):
            raise ValueError("ambiguous session cookies")
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return {**declared, "headers": headers, "test_data_only": True,
            "owned_objects_private": spec.get("owned_objects_private") is True}


def _rule_hash(resource, owner, attacker, owner_role, attacker_role):
    rule = dict(resource)
    if isinstance(rule.get("denied_roles"), list):
        rule["denied_roles"] = sorted(set(rule["denied_roles"]))
    return hashlib.sha256(json.dumps([rule, owner, attacker, owner_role, attacker_role],
                                    sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_declared_access(item, identities):
    """Exact rule comparison, including rule changes with unchanged markers."""
    proofs = bind_declared_access(item, identities, lambda left, right: left == right)
    keys = ("url", "owner_identity", "attacker_identity", "owner_marker", "owner_role", "attacker_role")
    proof = next((p for p in proofs if all(p.get(k) == item.get(k) for k in keys)
                  and (not item.get("access_rule_hash") or p["access_rule_hash"] == item["access_rule_hash"])), None)
    if not proof:
        raise ValueError("declared test resource unavailable or changed")
    return proof


def bind_declared_access(item, identities, matches):
    kind = item.get("vuln_class")
    collection = "functions" if kind == "bfla" else "protected_resources"
    bound = []
    for owner, identity in identities.items():
        if not isinstance(identity, dict) or not _credentials(identity.get("headers")):
            continue
        for resource in identity.get(collection) or []:
            if (not isinstance(resource, dict) or resource.get("test_data_only") is not True
                    or not isinstance(resource.get("marker"), str) or not resource["marker"]
                    or not matches(str(item.get("url") or ""), str(resource.get("url") or ""))):
                continue
            common = {**item, "url": resource["url"], "owner_identity": owner,
                      "owner_marker": resource["marker"], "test_resource": True}
            if kind == "authentication_bypass":
                if resource.get("authentication_required") is True:
                    bound.append({**common, "attacker_identity": "anonymous",
                                  "protected_marker": resource["marker"],
                                  "access_rule_hash": _rule_hash(resource, owner, "anonymous", None, None)})
                continue
            denied_roles = resource.get("denied_roles")
            owner_role = identity.get("role")
            if (not owner_role or not isinstance(denied_roles, list)
                    or not all(isinstance(role, str) and role for role in denied_roles)
                    or owner_role in denied_roles):
                continue
            for attacker, other in identities.items():
                if (attacker == owner or not isinstance(other, dict)
                        or other.get("role") not in denied_roles
                        or not _credentials(other.get("headers"))
                        or _credentials(other["headers"]) == _credentials(identity["headers"])):
                    continue
                bound.append({**common, "attacker_identity": attacker,
                              "owner_role": owner_role, "attacker_role": other["role"],
                              "access_rule_hash": _rule_hash(resource, owner, attacker, owner_role, other["role"])})
    return bound


def access_prerequisites(kind):
    if kind == "authentication_bypass":
        return ["authorized_test_identity", "protected_test_resource", "authentication_required", "protected_marker"]
    if kind == "bfla":
        return ["distinct_test_identities", "distinct_roles", "function_test_resource", "denied_role_rule", "protected_marker"]
    return ["distinct_test_identities", "owned_test_object", "owner_marker"]
