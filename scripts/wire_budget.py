"""One request allowance for a native worker child and its HTTP/browser adapters.

The worker runs one tool per process. A process-wide counter also covers
Playwright's helper thread; adapter-local counters never reset this allowance.
The parent settles the returned count. A killed child has no trusted count,
so the existing campaign reservation remains the conservative cost.
"""
from __future__ import annotations

from contextlib import contextmanager
import re
import threading

SCHEMA = "cco-wire-usage/1"
BLOCK_REASONS = {"", "campaign request budget exhausted", "campaign request blocked by policy", "campaign transport failed"}
_ACTIVE = None
_ACTIVATION_LOCK = threading.Lock()

HTTP_VALIDATORS = frozenset({
    "validate_sqli", "validate_ssti", "validate_command_injection", "validate_path_traversal",
    "validate_xss_reflection", "validate_stored_reflection", "validate_open_redirect",
    "validate_business_logic", "validate_field_binding", "validate_access_control", "validate_ssrf_oob",
    "validate_blind_oob", "validate_csrf", "validate_second_order", "validate_xxe", "validate_auth_bypass",
    "validate_idor", "validate_file_upload", "validate_deserialization", "validate_token_differential",
    "validate_token_roundtrip", "validate_finding", "session_vault_check",
})
HTTP_BROWSERS = frozenset({
    "browser_screenshot", "browser_extract_text", "browser_get_forms", "browser_extract_links",
    "browser_security_headers", "browser_cookie_audit", "browser_capture_requests", "browser_runtime_observe",
    "browser_console_logs", "browser_dom_xss_probe",
})
HTTP_HUNTERS = frozenset({
    "run_web_loop", "fuzz_attack_surface", "auto_fanout_variants", "exploit_confirmed",
})


class UnsupportedWireAccounting(ValueError):
    """Raised before an unsupported native or external transport is dispatched."""


class WireBudget:
    def __init__(self, limit: int, invocation_id: str):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("invalid reserved campaign request budget")
        if not isinstance(invocation_id, str) or not re.fullmatch(r"[a-f0-9]{32}", invocation_id):
            raise ValueError("invalid wire invocation identifier")
        self.limit = limit
        self.invocation_id = invocation_id
        self.used = 0
        self.blocked_reason = ""
        self._lock = threading.Lock()

    def consume(self):
        with self._lock:
            if self.blocked_reason:
                return False, self.blocked_reason
            if self.used >= self.limit:
                self.blocked_reason = "campaign request budget exhausted"
                return False, self.blocked_reason
            self.used += 1
            return True, "allowed"

    def stop(self, reason):
        if reason not in BLOCK_REASONS or not reason:
            raise ValueError("invalid campaign wire stop reason")
        with self._lock:
            if not self.blocked_reason:
                self.blocked_reason = reason

    def snapshot(self):
        with self._lock:
            return {"schema": SCHEMA, "invocation_id": self.invocation_id,
                    "limit": self.limit, "authorized_requests": self.used, "blocked_reason": self.blocked_reason}


@contextmanager
def campaign_wire_budget(limit: int, invocation_id: str):
    global _ACTIVE
    with _ACTIVATION_LOCK:
        if _ACTIVE is not None:
            raise ValueError("campaign wire budget already active")
        budget = WireBudget(limit, invocation_id)
        _ACTIVE = budget
    try:
        yield budget
    finally:
        with _ACTIVATION_LOCK:
            _ACTIVE = None


def current_budget():
    return _ACTIVE


def consume_request(gate=None):
    """Charge once after admission, immediately before the transport attempt."""
    budget = _ACTIVE
    if budget is None or getattr(gate, "accounts_campaign_requests", False):
        return True, "allowed"
    return budget.consume()


def note_blocked(reason):
    if _ACTIVE is not None:
        _ACTIVE.stop(reason)


def network_required(tool_name, args, engine):
    # Hunter PLAN invocations cannot use transports and need no wire adapter.
    if tool_name in {"hunter_run_web_loop", "hunter_auto_fanout_variants", "hunter_exploit_confirmed",
                     "hunter_fuzz_attack_surface"} and args.get("live") is False:
        return False
    return bool(engine.tool_capability(tool_name).get("network"))


def require_accounted_tool(tool_name, args, engine):
    if not engine._is_known_tool(tool_name):
        raise UnsupportedWireAccounting("worker tool is not registered")
    if not network_required(tool_name, args, engine):
        return
    supported = (tool_name in {"validator_" + name for name in HTTP_VALIDATORS}
                 or tool_name in {"browser_" + name for name in HTTP_BROWSERS}
                 or tool_name in {"hunter_" + name for name in HTTP_HUNTERS}
                 or tool_name in {"kali-tools_curl_request", "kali-tools_crawl_web_surface", "kali-tools_discover_web_surface"})
    if not supported:
        raise UnsupportedWireAccounting("campaign wire accounting unavailable for this tool")


def validate_usage(usage, *, limit, invocation_id):
    if (not isinstance(usage, dict) or usage.get("schema") != SCHEMA
            or set(usage) != {"schema", "invocation_id", "limit", "authorized_requests", "blocked_reason"}
            or usage.get("invocation_id") != invocation_id or usage.get("limit") != limit
            or isinstance(usage.get("limit"), bool) or not isinstance(usage.get("limit"), int)
            or isinstance(usage.get("authorized_requests"), bool)
            or not isinstance(usage.get("authorized_requests"), int)
            or not 0 <= usage["authorized_requests"] <= limit
            or usage.get("blocked_reason") not in BLOCK_REASONS):
        raise RuntimeError("invalid campaign wire usage")
    return usage["authorized_requests"]
