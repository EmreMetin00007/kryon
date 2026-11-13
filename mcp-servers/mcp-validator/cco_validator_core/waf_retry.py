"""WAF-block detection and bounded payload mutation retry for validators."""

from __future__ import annotations

import os
import sys

MAX_WAF_RETRIES = 3

_VALIDATOR_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REASONING_DIR = os.path.join(os.path.dirname(_VALIDATOR_ROOT), "mcp-reasoning")
if _REASONING_DIR not in sys.path:
    sys.path.insert(0, _REASONING_DIR)

try:
    from cco_reasoning_core.payloads import apply_operators, generate_variants
    from cco_reasoning_core.waf_profiles import classify_http, fingerprint_channels
except ImportError:  # pragma: no cover - validator still works without mutation
    apply_operators = None
    generate_variants = None
    classify_http = None
    fingerprint_channels = None


def _header_blob(resp: dict) -> str:
    headers = resp.get("headers") or {}
    if isinstance(headers, dict):
        return "\n".join(f"{key}: {value}" for key, value in headers.items())
    return str(headers)


def response_classification(resp: dict) -> dict:
    if classify_http is None or not resp:
        return {"classification": "unknown", "waf_vendor_hint": None}
    return classify_http(
        int(resp.get("status") or 0),
        _header_blob(resp),
        resp.get("text") or "",
    )


def response_is_waf_block(resp: dict) -> bool:
    if not resp or not resp.get("ok"):
        return False
    cls = response_classification(resp)
    if cls.get("classification") == "waf_block":
        return True
    status = resp.get("status")
    text = (resp.get("text") or "").lower()
    if status in (403, 406) and any(
        marker in text for marker in (
            "mod_security", "modsecurity", "attention required", "cf-ray",
            "request blocked", "the requested url was rejected",
        )
    ):
        return True
    return False


def vendor_from_response(resp: dict) -> str:
    if fingerprint_channels is None or not resp:
        return ""
    vendor, _, _ = fingerprint_channels(
        _header_blob(resp), "", resp.get("text") or "", int(resp.get("status") or 0)
    )
    return "" if vendor == "unknown" else vendor


def mutation_sets(payload: str, technique: str, resp: dict | None = None, limit: int = MAX_WAF_RETRIES):
    if generate_variants is None or not payload:
        return []
    vendor = vendor_from_response(resp) if resp else ""
    result = generate_variants(
        payload, technique, blocked_by=vendor, waf=vendor,
        generations=1, population=max(1, int(limit)),
    )
    return result.get("variants") or []


def apply_ops(payload: str, operators) -> str:
    if apply_operators is None:
        return payload
    return apply_operators(payload, operators or [])
