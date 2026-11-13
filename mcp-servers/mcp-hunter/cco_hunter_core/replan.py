"""Conservative next-step recommendations for an incomplete web run.

This module is read-only: it never starts requests, changes a session, or
claims that a skipped test passed. The caller decides whether to queue work
after scope, authorization and budget are checked again.
"""
from __future__ import annotations


_ACTIONS = {
    "rate_limit": ("wait_and_reassess", "Rate limit observed; pause requests and reassess the allowed rate."),
    "session": ("restore_test_session", "Restore the supplied test session before continuing."),
    "policy": ("review_scope_and_grant", "Review the current scope, program policy and grant."),
    "schema": ("repair_request_context", "Recover the exact request schema and required fields."),
    "transport": ("inspect_transport", "Resolve the transport failure before making more requests."),
    "budget": ("review_budget", "Review remaining request and validation budgets."),
    "identity": ("provide_test_identities", "Provide explicit test identities and owned-object markers."),
    "surface": ("discover_surface", "Collect an in-scope surface before selecting tests."),
    "unavailable": ("record_untested", "Keep unavailable checks explicitly untested."),
}


def _signals(report: dict) -> list[str]:
    texts = [str(report.get("stopped") or "")]
    fuzz = report.get("fuzz") if isinstance(report.get("fuzz"), dict) else {}
    texts.append(str(fuzz.get("stopped") or ""))
    for error in report.get("errors") or []:
        texts.append(str(error))
    for skipped in report.get("skipped") or []:
        texts.append(str(skipped.get("reason") or "") if isinstance(skipped, dict) else str(skipped))
    return [text.lower() for text in texts if text]


def replan_web_report(report: dict) -> dict:
    """Return bounded, explainable actions; do not mutate the source report."""
    if not isinstance(report, dict):
        return {"status": "invalid", "automatic_retry": False, "actions": []}
    if report.get("mode") == "PLAN":
        return {"status": "planned", "automatic_retry": False, "actions": []}
    signals = _signals(report)
    joined = "\n".join(signals)
    categories = []

    def add(category: str, matches: tuple[str, ...]) -> None:
        if any(match in joined for match in matches):
            categories.append(category)

    add("rate_limit", ("429", "rate limit", "rate_limit", "rate limited"))
    add("session", ("401", "session expired", "session unavailable", "redirected to login", "login redirect"))
    add("policy", ("blocked_scope", "blocked_approval", "blocked policy", "policy gate", "outside scope"))
    add("schema", ("invalid schema", "schema invalid", "missing required field", "request context"))
    add("transport", ("transport failure", "transport error", "connection error", "timeout"))
    add("budget", ("max_validations", "budget exhausted", "budget exceeded", "request budget"))
    add("identity", ("test identities", "owned object", "owned-object", "credential-bearing identity",
                     "declared test resource"))
    add("surface", ("0 probe", "surface queue empty", "yuzey kuyrugu bos"))
    add("unavailable", ("request-level policy unavailable", "request-level policy integration unavailable",
                        "no crawl_fn", "not auto-validated", "unverified"))
    if (report.get("errors") or report.get("skipped")) and not categories:
        categories.append("unavailable")
    if report.get("ok") is False and not categories:
        categories.append("unavailable")
    actions = [{"category": category, "action": _ACTIONS[category][0],
                "reason": _ACTIONS[category][1]} for category in categories]
    blocking = any(category in categories for category in
                   ("rate_limit", "session", "policy", "schema", "transport", "budget", "identity"))
    status = "blocked" if blocking else "incomplete" if actions else "review_coverage"
    return {"status": status, "automatic_retry": False, "actions": actions,
            "run_id": str(report.get("run_id") or ""),
            "note": "A run is not fully covered merely because no finding was confirmed."}
