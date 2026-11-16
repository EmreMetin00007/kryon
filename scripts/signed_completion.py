"""Versioned authenticated completion envelopes (kind='signed_completion', version=1).

Completion envelopes are produced exclusively at trusted evidence-producing
boundaries (Hunter/Validator host trust), never inferred from empty solver
receipts. Unknown or malformed versions fail closed without legacy fallback.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Sequence
from urllib.parse import urlsplit

import evidence_trust

COMPLETION_KIND = "signed_completion"
COMPLETION_VERSION = 1
COMPLETION_PURPOSE = "signed-completion"
MAX_COMPLETION_ENVELOPE_BYTES = 4096
MAX_CHECKS = 32
MAX_CHECK_NAME_LEN = 128
NEGATIVE_VERIFIED_OUTCOME = "negative_verified"
_PROFILE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\Z")


def compute_check_revision(
    scope_revision: str,
    policy_hash: str,
    profile: str,
    required_checks: Sequence[str],
) -> str:
    """Bind completion checks to current scope, policy hash, profile, and check list without leaking policy data."""
    if not isinstance(scope_revision, str) or not scope_revision:
        raise ValueError("scope_revision required")
    if not isinstance(policy_hash, str) or not policy_hash:
        raise ValueError("policy_hash required")
    if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
        raise ValueError("invalid profile")
    checks = [str(item) for item in required_checks if isinstance(item, str) and item]
    if not checks:
        raise ValueError("required_checks required")
    return hashlib.sha256(
        evidence_trust.canonical_bytes([scope_revision, policy_hash, profile, sorted(set(checks))])
    ).hexdigest()


def _valid_check_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or not value or len(value) > MAX_CHECKS:
        return None
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > MAX_CHECK_NAME_LEN:
            return None
        out.append(item)
    return out


def _origin_matches(left_url: str, right_url: str) -> bool:
    left, right = urlsplit(left_url), urlsplit(right_url)
    return (
        left.scheme.lower() in {"http", "https"}
        and bool(left.hostname)
        and (left.scheme.lower(), left.netloc.lower()) == (right.scheme.lower(), right.netloc.lower())
    )


def build_signed_completion(
    *,
    run_id: str,
    target: str,
    profile: str,
    target_scope: str,
    check_revision: str,
    required_checks: Sequence[str],
    completed_checks: Sequence[str],
    candidate_id: str = "",
    url: str = "",
    param: str = "",
    method: str = "GET",
    carrier: str = "query",
    identity: str = "anonymous",
    completion_status: str = "completed_clean",
    findings_count: int = 0,
    validation_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Produce an Ed25519-authenticated signed_completion v1 envelope at a trusted boundary."""
    if evidence_trust.public_only():
        raise ValueError("signed_completion must be produced at trusted host/MCP boundary")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ValueError("run_id required")
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target required")
    if not isinstance(profile, str) or not _PROFILE_RE.fullmatch(profile):
        raise ValueError("invalid profile")
    if not isinstance(target_scope, str) or not target_scope.strip():
        raise ValueError("target_scope required")
    if not isinstance(check_revision, str) or not check_revision.strip():
        raise ValueError("check_revision required")
    if completion_status != "completed_clean" or type(findings_count) is not int or findings_count != 0:
        raise ValueError("signed_completion requires completed_clean with 0 findings")
    req = _valid_check_list(list(required_checks))
    comp = _valid_check_list(list(completed_checks))
    if req is None or comp is None or not set(req) <= set(comp):
        raise ValueError("required_checks must be completed")
    vids = [str(v) for v in validation_ids if isinstance(v, str) and v]
    if len(vids) > MAX_CHECKS:
        raise ValueError("too many validation_ids")
    route_url = url or target
    exec_ctx = {
        "url": route_url,
        "param": str(param or ""),
        "method": str(method or "GET").upper(),
        "carrier": str(carrier or "query"),
        "identity": str(identity or "anonymous"),
    }
    completion_id = hashlib.sha256(
        evidence_trust.canonical_bytes(
            [COMPLETION_KIND, COMPLETION_VERSION, run_id, candidate_id, target, profile, check_revision, exec_ctx, req]
        )
    ).hexdigest()
    payload = {
        "kind": COMPLETION_KIND,
        "version": COMPLETION_VERSION,
        "completion_id": completion_id,
        "run_id": run_id,
        "candidate_id": str(candidate_id or ""),
        "target": target,
        "target_scope": target_scope,
        "profile": profile,
        "check_revision": check_revision,
        "completion_status": completion_status,
        "findings_count": 0,
        "required_checks": req,
        "completed_checks": comp,
        "validation_ids": vids,
        "execution_context": exec_ctx,
    }
    signed = evidence_trust.attest(payload, COMPLETION_PURPOSE)
    envelope = {"kind": COMPLETION_KIND, "version": COMPLETION_VERSION, **signed}
    if len(evidence_trust.canonical_bytes(envelope)) > MAX_COMPLETION_ENVELOPE_BYTES:
        raise ValueError("signed_completion exceeds bounded envelope size")
    return envelope


def verify_signed_completion(
    envelope: Any,
    *,
    expected_run_id: str | None = None,
    expected_candidate_id: str | None = None,
    require_candidate_id: bool = False,
    expected_target: str | None = None,
    expected_url: str | None = None,
    expected_param: str | None = None,
    expected_method: str | None = None,
    expected_carrier: str | None = None,
    expected_profile: str | None = None,
    expected_scope: str | None = None,
    expected_check_revision: str | None = None,
    has_confirmed_finding: bool = False,
) -> tuple[bool, dict[str, Any] | None, str]:
    """Strictly verify a signed_completion v1 envelope. Fails closed on any mismatch or unknown version."""
    if has_confirmed_finding:
        return False, None, "contradictory_positive_and_negative_evidence"
    if not isinstance(envelope, dict):
        return False, None, "invalid_or_missing_signed_evidence"
    if len(evidence_trust.canonical_bytes(envelope)) > MAX_COMPLETION_ENVELOPE_BYTES:
        return False, None, "invalid_or_missing_signed_evidence"
    if envelope.get("kind") != COMPLETION_KIND:
        return False, None, "invalid_or_missing_signed_evidence"
    version = envelope.get("version")
    if type(version) is not int or version != COMPLETION_VERSION:
        return False, None, "unsupported_signed_completion_version"
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False, None, "invalid_or_missing_signed_evidence"
    if payload.get("kind") != COMPLETION_KIND:
        return False, None, "invalid_or_missing_signed_evidence"
    payload_version = payload.get("version")
    if type(payload_version) is not int or payload_version != COMPLETION_VERSION:
        return False, None, "unsupported_signed_completion_version"
    if not evidence_trust.verify(evidence_trust.canonical_bytes(payload), envelope, COMPLETION_PURPOSE):
        return False, None, "invalid_or_missing_signed_evidence"
    if payload.get("completion_status") != "completed_clean":
        return False, None, "invalid_or_missing_signed_evidence"
    if type(payload.get("findings_count")) is not int or payload["findings_count"] != 0:
        return False, None, "contradictory_positive_and_negative_evidence"
    req = _valid_check_list(payload.get("required_checks"))
    comp = _valid_check_list(payload.get("completed_checks"))
    if req is None or comp is None or not set(req) <= set(comp):
        return False, None, "invalid_or_missing_signed_evidence"
    for field in ("completion_id", "run_id", "target", "target_scope", "profile", "check_revision"):
        val = payload.get(field)
        if not isinstance(val, str) or not val.strip():
            return False, None, "invalid_or_missing_signed_evidence"
    ctx = payload.get("execution_context")
    if not isinstance(ctx, dict):
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_run_id is not None and payload["run_id"] != expected_run_id:
        return False, None, "invalid_or_missing_signed_evidence"
    cand_id = payload.get("candidate_id", "")
    if require_candidate_id and (not isinstance(cand_id, str) or not cand_id):
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_candidate_id is not None and cand_id and cand_id != expected_candidate_id:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_target is not None:
        if not _origin_matches(payload["target"], expected_target):
            return False, None, "invalid_or_missing_signed_evidence"
    if expected_url is not None and ctx.get("url") != expected_url:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_param is not None and ctx.get("param", "") != expected_param:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_method is not None and ctx.get("method", "GET") != expected_method:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_carrier is not None and ctx.get("carrier", "query") != expected_carrier:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_profile is not None and payload.get("profile") != expected_profile:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_scope is not None and payload.get("target_scope") != expected_scope:
        return False, None, "invalid_or_missing_signed_evidence"
    if expected_check_revision is not None and payload.get("check_revision") != expected_check_revision:
        return False, None, "invalid_or_missing_signed_evidence"
    return True, payload, ""
