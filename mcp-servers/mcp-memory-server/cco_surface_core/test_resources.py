"""Bounded operator declarations, stored only inside an encrypted session.

A declaration is an access rule for synthetic data, not a validation result.
Changing it replaces the session secret reference and requires a new check.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

_LABEL = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")
_SCHEMA = "declared-test-resources/1"


def policy_context():
    path = str(Path(__file__).resolve().parents[2] / "mcp-validator")
    if path not in sys.path:
        sys.path.insert(0, path)
    from cco_validator_core.evidence import current_policy_hash, current_scope_revision
    return hashlib.sha256(json.dumps([current_scope_revision(), current_policy_hash()]).encode()).hexdigest()


def normalize_resources(target, resources, permits):
    from .session_store import _origin

    if (not _origin(target) or not isinstance(resources, dict)
            or set(resources) - {"role", "functions", "protected_resources", "identity_facts"}
            or not isinstance(resources.get("role"), str) or not _LABEL.fullmatch(resources["role"])):
        raise ValueError("invalid declared test resources")
    result = {"schema": _SCHEMA, "role": resources["role"], "policy_context": policy_context()}
    if "identity_facts" in resources:
        facts = resources["identity_facts"]
        if not isinstance(facts, list) or len(facts) > 32:
            raise ValueError("invalid identity facts")
        clean_facts = []
        for fact in facts:
            if (not isinstance(fact, dict) or set(fact) != {"field", "value", "source", "evidence", "confidence"}
                    or fact["field"] not in {"principal", "tenant", "role", "authority"}
                    or fact["source"] not in {"operator", "response_metadata", "differential_list"}
                    or fact["confidence"] not in {"declared", "observed", "inferred"}
                    or any(not isinstance(fact[k], str) or not 1 <= len(fact[k]) <= 256
                           or any(ord(c) < 32 for c in fact[k]) for k in ("value", "evidence"))):
                raise ValueError("invalid identity facts")
            clean_facts.append(dict(fact))
        result["identity_facts"] = clean_facts
    for collection in ("functions", "protected_resources"):
        rows = resources.get(collection, [])
        if not isinstance(rows, list) or len(rows) > 32:
            raise ValueError("invalid declared test resources")
        clean, seen = [], set()
        for row in rows:
            rule = "denied_roles" if collection == "functions" else "authentication_required"
            if (not isinstance(row, dict) or set(row) != {"url", "marker", "test_data_only", rule}
                    or row.get("test_data_only") is not True):
                raise ValueError("invalid declared test resources")
            url, marker = row["url"], row["marker"]
            if (not isinstance(url, str) or len(url) > 2048 or any(c in url for c in "\r\n\x00")
                    or _origin(url) != _origin(target) or urlsplit(url).fragment
                    or not permits(url) or not isinstance(marker, str) or not 1 <= len(marker) <= 512
                    or any(ord(c) < 32 for c in marker) or url in seen):
                raise ValueError("invalid declared test resources")
            if collection == "functions":
                roles = row[rule]
                if (not isinstance(roles, list) or not 1 <= len(roles) <= 8
                        or any(not isinstance(r, str) or not _LABEL.fullmatch(r) for r in roles)
                        or result["role"] in roles):
                    raise ValueError("invalid declared test resources")
                value = sorted(set(roles))
            else:
                if row[rule] is not True:
                    raise ValueError("invalid declared test resources")
                value = True
            clean.append({"url": url, "marker": marker, "test_data_only": True, rule: value})
            seen.add(url)
        result[collection] = sorted(clean, key=lambda r: r["url"])
    return result


def resolve_resources(entry, role, permits):
    """Resolve only the encrypted declaration in the current policy context."""
    resources = entry.get("test_resources")
    if resources is None:
        return {"role": role or "member", "functions": [], "protected_resources": []}
    if (not entry.get("secret_ref") or not isinstance(resources, dict)
            or resources.get("schema") != _SCHEMA or resources.get("policy_context") != policy_context()
            or (role and resources.get("role") != role)):
        raise ValueError("declared test resource unavailable or changed")
    public = {key: resources.get(key) for key in ("role", "functions", "protected_resources")}
    if "identity_facts" in resources:
        public["identity_facts"] = resources["identity_facts"]
    normalized = normalize_resources(entry["target"], public, permits)
    if normalized != resources:
        raise ValueError("declared test resource unavailable or changed")
    return public
