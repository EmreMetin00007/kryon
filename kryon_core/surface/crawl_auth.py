"""Separate endpoint authorization restrictions from principal session loss.

Response callbacks only queue a check. A gated, marker-verified control runs
outside the Playwright event callback before discovery continues.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from .frontier import metadata_url


def login_redirect(url: str, location: str) -> bool:
    path = urlsplit(urljoin(url, location)).path
    for _ in range(8):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return bool(re.search(r"/(?:login|signin|sign-in|sso|auth/login)\b", path, re.I))


class CrawlAuthBoundary:
    def __init__(self, primary_url: str, authenticated: bool = False) -> None:
        self.primary_url = primary_url
        self.authenticated = authenticated
        self.pending: dict[tuple[str, int], dict[str, Any]] = {}
        self.restrictions: list[dict[str, Any]] = []
        self.reason = ""
        self.checks = 0

    def observe(self, url: str, status: int, location: str = "") -> str:
        if status == 429:
            self.reason = "http_429"
        elif status in {502, 503, 504}:
            self.reason = "service_degradation"
        elif status in {401, 403} or (
            status in {301, 302, 303, 307, 308} and location and login_redirect(url, location)
        ):
            entry = {"url": metadata_url(url), "status": status}
            if not self.authenticated:
                if entry not in self.restrictions:
                    self.restrictions.append(entry)
            elif url == self.primary_url:
                self.reason = f"http_{status}" if status in {401, 403} else "login_redirect"
            else:
                self.pending[(url, status)] = entry
        return self.reason

    def resolve(self, check: Any) -> str:
        if self.reason or not self.pending:
            return self.reason
        self.checks += 1
        try:
            result = check() if callable(check) else {"status": "unknown"}
        except Exception:
            result = {"status": "unknown"}
        status = result.get("status")
        if status == "fresh":
            for entry in self.pending.values():
                if entry not in self.restrictions:
                    self.restrictions.append(entry)
            self.pending.clear()
        elif status == "rate_limited":
            self.reason = "http_429"
        elif result.get("reason") == "service_degradation":
            self.reason = "service_degradation"
        elif status == "expired" or result.get("reason") == "marker_missing":
            self.reason = "session_expired"
        else:
            self.reason = "session_check_required"
        return self.reason

    def summary(self) -> dict[str, Any]:
        return {
            "authorization_restrictions": self.restrictions,
            "session_checks": self.checks,
            "session_recovery": self.reason in {"http_401", "http_403", "login_redirect", "session_expired"},
            "session_uncertain": self.reason == "session_check_required",
        }
