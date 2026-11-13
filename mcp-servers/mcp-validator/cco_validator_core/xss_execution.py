"""Bounded reflected-XSS browser oracle with isolated, read-only contexts."""
from __future__ import annotations

import hashlib
from http.cookies import SimpleCookie
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .evidence import redact_url, response_evidence

TOOL = "validator_validate_xss_reflection"


def options(rule):
    if (not isinstance(rule, dict) or set(rule) - {"enabled", "max_browser_requests", "wait_ms"}
            or rule.get("enabled") is not True):
        raise ValueError("browser execution is not enabled by program policy")
    maximum, wait = rule.get("max_browser_requests", 8), rule.get("wait_ms", 100)
    if type(maximum) is not int or not 4 <= maximum <= 12 or type(wait) is not int or not 0 <= wait <= 2000:
        raise ValueError("invalid browser execution bounds")
    return maximum, wait


def origin(url):
    parsed = urlsplit(url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError("invalid browser target")
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)


def rounds(url, param):
    origin(url)
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    values = [value for name, value in pairs if name == param]
    if not param or len(values) != 1 or values[0] in {"<redacted>", "<unavailable>"}:
        raise ValueError("one observed query parameter is required")
    plans = [{"role": "baseline", "url": url, "nonce": ""}]
    for role in ("inert-control", "execution-probe", "execution-repeat"):
        nonce = "cco-xss-" + secrets.token_hex(16)
        payload = (f'<svg data-cco-xss="{nonce}"></svg>' if role == "inert-control"
                   else f'<svg onload="alert(\'{nonce}\')"></svg>')
        query = [(name, payload if name == param else value) for name, value in pairs]
        plans.append({"role": role, "url": urlunsplit(parsed._replace(query=urlencode(query))), "nonce": nonce})
    return plans


def verdict(result, plans):
    observations = result.get("observations", [])
    trace = result.get("request_evidence", [])
    if (result.get("completed") is not True or result.get("browser") != "chromium"
            or result.get("fallback") is not False or not result.get("browser_version")
            or len(plans) != 4 or len(observations) != 4 or len(trace) != 4):
        return "INCONCLUSIVE"
    for row, request, plan in zip(observations, trace, plans):
        expected = hashlib.sha256(plan["nonce"].encode()).hexdigest() if plan["nonce"] else ""
        if (row.get("role") != plan["role"] or row.get("nonce_sha256") != expected
                or row.get("url_sha256") != hashlib.sha256(plan["url"].encode()).hexdigest()
                or request.get("role") != "browser-xss-" + plan["role"]
                or request.get("request_url") != redact_url(plan["url"])
                or not request.get("transport_ok") or request.get("status") != 200
                or request.get("method") != "GET"):
            return "INCONCLUSIVE"
    if any(row["dialogs_seen"] for row in observations[:2]):
        return "INCONCLUSIVE"
    return "CONFIRMED" if all(row["correlated_alerts"] > 0 for row in observations[2:]) else "INCONCLUSIVE"


def validate(url, param, headers, method, body_template, revision):
    """Opt in through policy; reuse the campaign's scope/session/wire gate.

    None preserves the legacy reflection result when execution is disabled.
    A configured but incomplete browser check always stays inconclusive.
    """
    from .egress import current_wire_gate
    from .evidence import current_scope_revision, current_policy_hash

    scripts = str(Path(__file__).resolve().parents[3] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from policy_engine import PolicyEngine, ScopeResolver
    from wire_budget import consume_request

    plans = []
    try:
        engine = PolicyEngine()
        rule = engine.program_policy.get("xss_execution")
        if rule is None or (isinstance(rule, dict) and rule.get("enabled") is False):
            return None
        maximum, wait = options(rule)
        if method.upper() != "GET" or body_template:
            raise ValueError("browser execution requires a query parameter on a read-only GET")
        plans = rounds(url, param)
        if not ScopeResolver(scope_file=engine.scope_file).permits_url(url):
            raise ValueError("browser target is outside scope")
        inherited = current_wire_gate()

        def context_is_current():
            return revision == (current_scope_revision(), current_policy_hash())

        def gate(method, target, actual_headers):
            if not context_is_current():
                return False, "browser scope or policy changed"
            if inherited is not None:
                return inherited(method, target, actual_headers)
            decision = engine.validate_wire_invocation(TOOL, {
                "target_url": target, "target": target, "url": target,
                "method": method, "headers": actual_headers})
            if not decision.get("allowed"):
                return False, str(decision.get("reason") or "browser policy denied")
            return consume_request(engine)

        if not context_is_current():
            raise ValueError("browser scope or policy changed")
        result = run_browser(plans, headers, engine, gate, maximum, wait)
        if not context_is_current():
            result.update(completed=False, error_kind="scope_or_policy_changed")
        return plans, result
    except Exception as exc:
        return plans, {"completed": False, "observations": [], "request_evidence": [],
                       "browser_requests": 0, "error_kind": type(exc).__name__}


def run_browser(plans, headers, engine, gate, maximum=8, wait_ms=100):
    # FastMCP may invoke synchronous tools from an asyncio loop. Preserve the
    # validator context while keeping Playwright's Sync API off that loop.
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _run_browser(plans, headers, engine, gate, maximum, wait_ms)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(copy_context().run, _run_browser,
                           plans, headers, engine, gate, maximum, wait_ms).result()


def _run_browser(plans, headers, engine, gate, maximum, wait_ms):
    """No shared session, CDP attach, injected execution flag or HTTP fallback.

    Browser dialogs count only when the top-level page is the exact injected
    URL, and their alert text is the fresh random nonce for that round.
    """
    browser_path = str(Path(__file__).resolve().parents[2] / "mcp-browser")
    if browser_path not in sys.path:
        sys.path.insert(0, browser_path)
    from cco_browser_core.policy import install_readonly_request_gate
    from playwright.sync_api import sync_playwright

    expected_origin = origin(plans[0]["url"])
    observations, trace = [], []
    admitted = 0
    cookie_text = next((value for name, value in headers.items() if name.lower() == "cookie"), "")
    cookies = SimpleCookie()
    cookies.load(cookie_text)
    public_headers = {name: value for name, value in headers.items() if name.lower() != "cookie"}

    def budget_gate(method, url, actual_headers):
        nonlocal admitted
        if admitted >= maximum:
            return False, "browser request budget exhausted"
        allowed, reason = gate(method, url, actual_headers)
        if allowed:
            admitted += 1
        return allowed, reason

    def request_filter(url, _headers):
        try:
            return origin(url) == expected_origin
        except ValueError:
            return False

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                version = browser.version
                for plan in plans:
                    context = browser.new_context(service_workers="block", accept_downloads=False,
                        ignore_https_errors=True, extra_http_headers=public_headers)
                    try:
                        if cookies:
                            parsed = urlsplit(plan["url"])
                            cookie_origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
                            context.add_cookies([{"name": name, "value": morsel.value, "url": cookie_origin}
                                                 for name, morsel in cookies.items()])
                        state = install_readonly_request_gate(context, engine, TOOL,
                            wire_gate=budget_gate, request_filter=request_filter, stop_on_denial=True)
                        page = context.new_page()
                        dialogs, correlated = [], []

                        def on_dialog(dialog):
                            dialogs.append(True)
                            if (dialog.type == "alert" and plan["nonce"] and dialog.message == plan["nonce"]
                                    and page.url == plan["url"] and getattr(dialog, "page", page) is page):
                                correlated.append(True)
                            dialog.dismiss()

                        page.on("dialog", on_dialog)
                        started = time.monotonic()
                        response = page.goto(plan["url"], wait_until="domcontentloaded", timeout=15000)
                        page.wait_for_timeout(wait_ms)
                        if (state["stopped"] or response is None or response.status != 200
                                or response.url != plan["url"] or page.url != plan["url"]):
                            return {"completed": False, "observations": observations, "request_evidence": trace,
                                    "browser_requests": admitted, "error_kind": state["reason"] or "navigation_incomplete"}
                        body = response.body().decode("utf-8", "replace")
                        trace.append(response_evidence({"ok": True, "status": response.status, "text": body,
                            "headers": response.headers, "time": time.monotonic() - started,
                            "request_method": "GET", "final_url": response.url}, "browser-xss-" + plan["role"], 0))
                        observations.append({"role": plan["role"], "dialogs_seen": len(dialogs),
                            "correlated_alerts": len(correlated),
                            "url_sha256": hashlib.sha256(plan["url"].encode()).hexdigest(),
                            "nonce_sha256": hashlib.sha256(plan["nonce"].encode()).hexdigest() if plan["nonce"] else ""})
                    finally:
                        context.close()
            finally:
                browser.close()
        return {"completed": True, "observations": observations, "request_evidence": trace,
                "browser_requests": admitted, "browser": "chromium", "browser_version": version, "fallback": False}
    except Exception as exc:
        return {"completed": False, "observations": observations, "request_evidence": trace,
                "browser_requests": admitted, "error_kind": type(exc).__name__}
