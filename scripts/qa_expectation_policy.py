"""Neutral versioned QA Expectation Policy evaluator (Policy-Verified QA Mode)."""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

SCHEMA = "qa-expectation-policy/1"
_TEMPLATE_SEG_RE = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


def load_qa_policy(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    """Load and validate a versioned qa-expectation-policy/1 document."""
    if isinstance(source, dict):
        data = dict(source)
    else:
        path = Path(source).expanduser().resolve(strict=True)
        data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("QA policy must be a JSON object")
    if data.get("schema") != SCHEMA:
        raise ValueError(f"unsupported QA policy schema: {data.get('schema')!r}")
    for key in ("access_rules", "field_binding_rules", "telemetry_controls"):
        val = data.get(key)
        if val is not None and not isinstance(val, list):
            raise ValueError(f"QA policy {key} must be a list")
    return data


def _path_matches(pattern: str, actual_path: str) -> bool:
    pat = (pattern or "").strip()
    if not pat:
        return False
    if "://" in pat:
        pat = urlsplit(pat).path or "/"
    act = urlsplit(actual_path).path if "://" in actual_path else actual_path
    pat_norm = "/" + pat.strip("/")
    act_norm = "/" + (act or "/").strip("/")
    if pat_norm == act_norm:
        return True
    if "{" in pat_norm and "}" in pat_norm:
        parts = _TEMPLATE_SEG_RE.split(pat_norm)
        regex = "^" + r"[^/]+".join(re.escape(part) for part in parts) + "$"
        if re.fullmatch(regex, act_norm):
            return True
    if "*" in pat_norm or "?" in pat_norm:
        return fnmatch.fnmatch(act_norm, pat_norm)
    return False


def _match_rules(
    rules: list[Any],
    *,
    method: str,
    path: str,
    category: str = "",
) -> tuple[dict[str, Any] | None, str]:
    norm_method = str(method or "GET").upper()
    norm_cat = str(category or "").strip()
    matches: list[dict[str, Any]] = []
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        rule_method = str(raw.get("method") or "GET").upper()
        if rule_method not in {"*", norm_method}:
            continue
        rule_cat = str(raw.get("category") or "").strip()
        if norm_cat and rule_cat and rule_cat != norm_cat:
            continue
        if _path_matches(str(raw.get("path_pattern") or raw.get("path") or ""), path):
            matches.append(raw)
    if not matches:
        return None, "oracle_gap:missing_policy_rule"
    signatures = {
        json.dumps(
            {
                "expect": m.get("expect"),
                "allowed_roles": sorted(m.get("allowed_roles") or []),
                "denied_roles": sorted(m.get("denied_roles") or []),
                "restricted_fields": sorted(m.get("restricted_fields") or []),
                "allowed_fields": sorted(m.get("allowed_fields") or []),
                "denied_statuses": sorted(m.get("denied_statuses") or []),
            },
            sort_keys=True,
        )
        for m in matches
    }
    if len(signatures) > 1:
        return None, "oracle_gap:conflicting_policy_rule"
    return matches[0], ""


def match_access_rule(
    policy: dict[str, Any],
    *,
    method: str,
    path: str,
    category: str,
) -> tuple[dict[str, Any] | None, str]:
    """Match an access/telemetry rule deterministically; missing/conflicting -> oracle_gap."""
    rules = list(policy.get("access_rules") or [])
    if category == "telemetry_control":
        rules = [*list(policy.get("telemetry_controls") or []), *rules]
    return _match_rules(rules, method=method, path=path, category=category)


def match_field_binding_rule(
    policy: dict[str, Any],
    *,
    method: str,
    path: str,
) -> tuple[dict[str, Any] | None, str]:
    """Match a field-binding rule deterministically; missing/conflicting -> oracle_gap."""
    rules = list(policy.get("field_binding_rules") or [])
    return _match_rules(rules, method=method, path=path, category="field_binding")


def evaluate_access_rule(
    rule: dict[str, Any],
    *,
    caller_role: str,
    caller_tenant: str,
    owner_tenant: str = "",
    owner_alias: str = "",
    caller_alias: str = "",
    status: int | None,
    anon_status: int | None = None,
    observed_record_tenant: str = "",
    leaked_restricted_fields: Sequence[str] | None = None,
    is_challenge_blocked: bool = False,
) -> tuple[str, str]:
    """Deterministically adjudicate an observation against a QA Expectation Policy rule.

    Returns (verdict, detail_reason) where verdict is CONFIRMED | UNCONFIRMED | INCONCLUSIVE.
    """
    expect = str(rule.get("expect") or "").strip()
    allowed_roles = {str(r).strip() for r in (rule.get("allowed_roles") or []) if str(r).strip()}
    denied_roles = {str(r).strip() for r in (rule.get("denied_roles") or []) if str(r).strip()}
    denied_statuses = {int(s) for s in (rule.get("denied_statuses") or [401, 403, 404])}
    role_str = str(caller_role or "").strip()

    if is_challenge_blocked or status is None or status == 429 or status >= 500:
        if expect == "challenge_or_authz_distinct" and is_challenge_blocked:
            return "UNCONFIRMED", "telemetry_challenge_distinct"
        return "INCONCLUSIVE", "transport_or_challenge_interference"

    if expect == "challenge_or_authz_distinct":
        if status in denied_statuses:
            return "UNCONFIRMED", "telemetry_control_passed"
        return "CONFIRMED", "telemetry_control_unexpected_allow"

    if expect == "deny_cross_tenant":
        if role_str and role_str in allowed_roles:
            return ("UNCONFIRMED", "allowed_role") if 200 <= status < 300 else ("INCONCLUSIVE", "allowed_role_denied")
        if status in denied_statuses:
            return "UNCONFIRMED", "cross_tenant_denied"
        if 200 <= status < 300:
            if (
                (observed_record_tenant and caller_tenant and observed_record_tenant != caller_tenant)
                or (owner_tenant and caller_tenant and owner_tenant != caller_tenant)
            ):
                if anon_status is None or anon_status in {401, 403, 404}:
                    return "CONFIRMED", "cross_tenant_record_accessible"
                return "INCONCLUSIVE", "anonymous_baseline_not_denied"
        return "INCONCLUSIVE", "cross_tenant_ambiguous_response"

    if expect == "deny_non_owner_or_redact_fields":
        if role_str and role_str in allowed_roles:
            return ("UNCONFIRMED", "allowed_role") if 200 <= status < 300 else ("INCONCLUSIVE", "allowed_role_denied")
        if status in denied_statuses:
            return "UNCONFIRMED", "non_owner_denied"
        if 200 <= status < 300:
            if owner_alias and caller_alias and owner_alias != caller_alias:
                restricted = list(rule.get("restricted_fields") or [])
                if not restricted or (leaked_restricted_fields and any(f in restricted for f in leaked_restricted_fields)):
                    if anon_status is None or anon_status in {401, 403, 404}:
                        return "CONFIRMED", "restricted_owner_fields_exposed"
                    return "INCONCLUSIVE", "anonymous_baseline_not_denied"
                return "UNCONFIRMED", "restricted_fields_absent"
        return "INCONCLUSIVE", "owner_rule_inconclusive"

    if expect == "deny_unlisted_roles":
        is_allowed = role_str in allowed_roles if allowed_roles else (role_str not in denied_roles)
        if is_allowed:
            return ("UNCONFIRMED", "allowed_role_permitted") if 200 <= status < 300 else ("INCONCLUSIVE", "allowed_role_denied")
        if status in denied_statuses:
            return "UNCONFIRMED", "denied_role_blocked"
        if 200 <= status < 300:
            if anon_status is None or anon_status in {401, 403, 404}:
                return "CONFIRMED", "disallowed_role_permitted"
            return "INCONCLUSIVE", "anonymous_baseline_not_denied"
        return "INCONCLUSIVE", "role_rule_inconclusive"

    if expect in {"allow_authenticated", "allow_tenant_scoped"}:
        if 200 <= status < 300:
            if expect == "allow_tenant_scoped" and observed_record_tenant and caller_tenant and observed_record_tenant != caller_tenant:
                return "CONFIRMED", "tenant_scope_escaped"
            return "UNCONFIRMED", "expected_authenticated_allow"
        return "INCONCLUSIVE", "unexpected_denial"

    return "INCONCLUSIVE", "unsupported_policy_expectation"
